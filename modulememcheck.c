#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kmemcheck.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/page-flags.h>
#include <linux/percpu.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/hash.h>

#include <asm/cacheflush.h>
#include <asm/modulememcheck.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

struct modulememcheck_alloc_obj {
	struct list_head list;
	//struct hlist_node hlist;
	unsigned long address;
	unsigned long size;		// unit : B
	unsigned long pages;	// amount of pages
};

/*
#define MMC_ALLOC_HASH_BITS 5
#define MMC_ALLOC_TABLE_SIZE (1 << MMC_ALLOC_HASH_BITS)
/ hash table to store all the allcation struct /
static struct hlist_head modulememcheck_allocations[MMC_ALLOC_TABLE_SIZE];
*/

/* ascending order by address */
static struct list_head modulememcheck_allocations_head;

#define MODULEMEMCHECK_ENABLED		1
#define MODULEMEMCHECK_DISABLED		0
static int modulememcheck_enabled = MODULEMEMCHECK_DISABLED;

/* assigned in the fault handler and used in the trap, store the hide address */
unsigned long hide_address;

/* function pointer variable  */
static bool (*modulememcheck_pf_handler)(struct pt_regs *regs, unsigned long address, unsigned long error_code) = NULL;


static pte_t *modulememcheck_addr_to_pte(unsigned long address)
{
	pte_t *pte;
	unsigned int level;
	pte = lookup_address(address, &level);
	if (!pte)
		return NULL;
	return pte;
}

static bool modulememcheck_is_interest(unsigned long address)
{
	pte_t *pte;
	struct modulememcheck_alloc_obj *pos;

	/* check if the pte is interested */

	if (list_empty(&modulememcheck_allocations_head))
		return false;

	list_for_each_entry(pos, &modulememcheck_allocations_head, list) {
		if (address >= pos->address) {
			if (address < (pos->address + PAGE_SIZE * pos->pages)) {
				pte = modulememcheck_addr_to_pte(address);
				if (pte)
					return true;
				else 
					break;
			} else {
				break;
			}
		}
	}	
	return false;
}

int __init modulememcheck_init(void)
{
#ifdef CONFIG_SMP
	/*
	 * Limit SMP to use a single CPU. We rely on the fact that this code
	 * runs before SMP is set up.
	 */
	if (setup_max_cpus > 1) {
		printk(KERN_INFO
			"modulememcheck: Limiting number of CPUs to 1.\n");
		setup_max_cpus = 1;
	}
#endif

	/*
	for (i = 0; i < MMC_ALLOC_TABLE_SIZE; i++) {
		INIT_HLIST_HEAD(&modulememcheck_allocations[i]);
	}
	*/
	INIT_LIST_HEAD(&modulememcheck_allocations_head);

	printk(KERN_INFO "modulememcheck: Initialized\n");
	return 0;
}

early_initcall(modulememcheck_init);

static int modulememcheck_show_addr(unsigned long address)
{
	pte_t *pte;
	printk("[MMC]->modulememcheck_show_addr : modulememcheck show addr %lx! \n", address);
	pte = modulememcheck_addr_to_pte(address);
	if (!pte)
		return 0;

	set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
	__flush_tlb_one(address);
	return 1;
}

static int modulememcheck_hide_addr(unsigned long address)
{
	pte_t *pte;
	printk("[MMC]->modulememcheck_hide_addr : modulememcheck hide addr %lx! \n", address);
	pte = modulememcheck_addr_to_pte(address);
	if (!pte)
		return 0;

	set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
	__flush_tlb_one(address);
	return 1;
}

static void modulememcheck_set_singlestep(struct pt_regs *regs)
{
	regs->flags |= X86_EFLAGS_TF;
	regs->flags &= ~X86_EFLAGS_IF;
}

static void modulememcheck_clear_singlestep(struct pt_regs *regs)
{
	regs->flags &= ~X86_EFLAGS_TF;
	regs->flags |= X86_EFLAGS_IF;
}

bool modulememcheck_fault(struct pt_regs *regs, unsigned long address,
	unsigned long error_code)
{
	if (modulememcheck_enabled == MODULEMEMCHECK_DISABLED)
		return false;

	BUG_ON(!modulememcheck_pf_handler);

	BUG_ON(!regs);

	if (regs->flags & X86_VM_MASK)
		return false;
	if (regs->cs != __KERNEL_CS)
		return false;

	//printk("[MODULE MEM CHECK] : modulememcheck falut ! \n");
	
	if (!modulememcheck_is_interest(address))
		return false;
	
	modulememcheck_pf_handler(regs, address, error_code);
	
	// make the pte present
	modulememcheck_show_addr(address);
	hide_address = address;

	// for single step
	modulememcheck_set_singlestep(regs);

	return true;
}

bool modulememcheck_trap(struct pt_regs *regs)
{
	modulememcheck_hide_addr(hide_address);
	modulememcheck_clear_singlestep(regs);
	return true;
}

static void modulememcheck_allocations_add(struct modulememcheck_alloc_obj *obj)
{
	struct modulememcheck_alloc_obj *pos;

	if (list_empty(&modulememcheck_allocations_head)) {
		list_add(&obj->list, &modulememcheck_allocations_head);
		return ;
	}

	list_for_each_entry(pos, &modulememcheck_allocations_head, list) {
		if (obj->address < pos->address) {
			break;
		}
	}	
	__list_add(&obj->list, pos->list.prev, &pos->list);

	/*
	struct hlist_head *head;
	head = &modulememcheck_allocations[hash_ptr(obj->address, MMC_ALLOC_HASH_BITS)];
	hlist_add_head(obj->hlist, head);
	*/
}

static void modulememcheck_allocations_del(struct modulememcheck_alloc_obj *del_obj)
{
	list_del(&del_obj->list);
	//hlist_del(&del_obj->hlist);
}

static void modulememcheck_allocations_clear(void)
{
	struct modulememcheck_alloc_obj *pos, *node;

	if (list_empty(&modulememcheck_allocations_head))
		return ;

	list_for_each_entry_safe(pos, node, &modulememcheck_allocations_head, list) {
		list_del(&pos->list);
		kfree(pos);
	}
	/*
	struct hlist_head *head;
	struct modulememcheck_alloc_obj *obj;
	struct hlist_node *node = NULL;
	struct hlist_node *tmp = NULL;
	for (i = 0; i < MMC_ALLOC_TABLE_SIZE; ++i) {
		head = &modulememcheck_allocations[i];
		hlist_for_each_entry_safe(obj, node, tmp, head, hlist) {
			hlist_del(&obj->hlist);
			kfree(obj);
		}
	}
	*/
}

static struct modulememcheck_alloc_obj *modulememcheck_allocations_lookup(unsigned long address)
{
	struct modulememcheck_alloc_obj *pos;

	if (list_empty(&modulememcheck_allocations_head))
		return NULL;

	list_for_each_entry(pos, &modulememcheck_allocations_head, list) {
		if (address == pos->address) {
			return pos;
		}
		if (address > pos->address) {
			break;
		}
	}
	return NULL;
	
	/*
	struct hlist_head *head;
	struct hlist_node *node;
	struct modulememcheck_alloc_obj *obj = NULL;

	head = &modulememcheck_allocations[hash_ptr(address, MMC_ALLOC_HASH_BITS)];
	hlist_for_each_entry(obj, node, head, hlist) {
		if (obj->address == address) {
			return obj;
		}
	}
	*/
	return NULL;
}

bool modulememcheck_alloc(unsigned long address, unsigned long size)
{
	struct modulememcheck_alloc_obj *obj;
	int i;
	obj = (struct modulememcheck_alloc_obj *)kmalloc(sizeof(struct modulememcheck_alloc_obj), GFP_KERNEL);
	if (!obj) {
		printk("[MMC]->modulememcheck_alloc :not enough memory\n");
		return false;
	}

	obj->address = address;
	obj->size = size;
	
	/* hide all the pages related to the [address, address + size] */	
	obj->pages = (size / PAGE_SIZE) + ((size % PAGE_SIZE) ? 1 : 0);
	for (i = 0; i < obj->pages; i++) {
		modulememcheck_hide_addr(address);
		address += PAGE_SIZE;
	}
	
	modulememcheck_allocations_add(obj);

	return true;
}
EXPORT_SYMBOL(modulememcheck_alloc);

void modulememcheck_free(unsigned long address_start)
{
	struct modulememcheck_alloc_obj *obj;
	obj = modulememcheck_allocations_lookup(address_start);
	if (obj) {
		int i;
		unsigned long address = obj->address;
		/* recovry all the pages related to the [address, address + size] */	
		for (i = 0; i < obj->pages; i++) {
			modulememcheck_show_addr(address);
			address += PAGE_SIZE;
		}
	
		modulememcheck_allocations_del(obj);
		kfree(obj);
	}
}
EXPORT_SYMBOL(modulememcheck_free);

/* if have registered before or handler is NULL,  then failed */
bool register_modulememcheck_pf_handler(bool (*handler)(struct pt_regs *regs, unsigned long address, unsigned long error_code))
{
	if ((handler == NULL) ||
			(modulememcheck_enabled == MODULEMEMCHECK_ENABLED))
		return false;
	modulememcheck_pf_handler = handler;
	modulememcheck_enabled = MODULEMEMCHECK_ENABLED;
	printk("[MMC] : registered!\n");
	return true;
}
EXPORT_SYMBOL(register_modulememcheck_pf_handler);

void unregister_modulememcheck_pf_handler(void)
{
	if (modulememcheck_enabled == MODULEMEMCHECK_ENABLED) {
		modulememcheck_enabled = MODULEMEMCHECK_DISABLED;
		modulememcheck_pf_handler = NULL;
	 
		// clear the allocations objs
		modulememcheck_allocations_clear();

		printk("[MMC] : unregistered!\n");
	}
}
EXPORT_SYMBOL(unregister_modulememcheck_pf_handler);
