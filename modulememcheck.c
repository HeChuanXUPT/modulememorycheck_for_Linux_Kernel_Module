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
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/preempt.h>	// preempt_*

#define MMC_DEBUG_ON
#ifdef MMC_DEBUG_ON
#define MMC_DEBUG(X) printk(KERN_ALERT X "\n")
#else 
#define MMC_DEBUG(X) {}
#endif

#define HC_2M_PAGE_SHIFT 22
#define HC_2M_PAGE_SIZE	(_AC(1,UL) << HC_2M_PAGE_SHIFT)
#define HC_2M_PAGE_MASK	(~(HC_2M_PAGE_SIZE-1))

struct modulememcheck_alloc_obj {
	struct list_head list;
	unsigned long address;
	unsigned long page_address;
	unsigned long size;		// unit : B
	unsigned long pages;	// amount of pages
	int type;	// is a 2M page ? 1(yse) : 0(no)
};

static DEFINE_SPINLOCK(mmc_allocations_lock);
//static DEFINE_PER_CPU(long, modulememcheck_regs_flags);

/* ascending order by address */
static struct list_head modulememcheck_allocations_head;

#define MODULEMEMCHECK_ENABLED		1
#define MODULEMEMCHECK_DISABLED		0
static int modulememcheck_enabled = MODULEMEMCHECK_DISABLED;

/* assigned in the fault handler and used in the trap, store the hide address */
unsigned long hide_address;

/* function pointer variable  */
static bool (*modulememcheck_pf_handler)(struct pt_regs *regs, unsigned long address, unsigned long error_code, unsigned long buffer_addr) = NULL;


static pte_t *modulememcheck_addr_to_pte(unsigned long address)
{
	pte_t *pte;
	unsigned int level;
	pte = lookup_address(address, &level);
	return pte;
}

/*  0 : not interest
 *  1 : interest pte, not address
 *  other : interest address, the kernel address is > 1
 */
static unsigned long modulememcheck_is_interest(unsigned long address)
{
	struct modulememcheck_alloc_obj *pos;

	/* check if the pte and address is interested */

	if (list_empty(&modulememcheck_allocations_head))
		return 0;

	list_for_each_entry(pos, &modulememcheck_allocations_head, list) {
		if (address >= pos->page_address) {
			unsigned long psize;
			psize = pos->type ? HC_2M_PAGE_SIZE : PAGE_SIZE;
			if (address < (pos->page_address + psize * pos->pages)) {
				if (address >= pos->address && address < (pos->address + pos->size))
					return pos->address;
				else 
					return 1;
			}
		} else 
			break;
	}	

	return 0;
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

	INIT_LIST_HEAD(&modulememcheck_allocations_head);

	printk(KERN_INFO "modulememcheck: Initialized\n");
	return 0;
}

early_initcall(modulememcheck_init);

static int modulememcheck_show_addr(unsigned long address)
{
	pte_t *pte;
	//printk("[MMC]->modulememcheck_show_addr : modulememcheck show addr %lx! \n", address);
	pte = modulememcheck_addr_to_pte(address);
	if (!pte)
		return 0;
	/*
	if (pte_val(*pte) == 0) {		// need load 
	//	if (vmalloc_fault(address) < 0)
		printk(KERN_ALERT "MMC: PTE ===== 00000000000000000000000\n");
		return 0;
	}
*/
	set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
	__flush_tlb_one(address);
	return 1;
}

static int modulememcheck_hide_addr(unsigned long address)
{
	pte_t *pte;
	//printk("[MMC]->modulememcheck_hide_addr : modulememcheck hide addr %lx! \n", address);
	pte = modulememcheck_addr_to_pte(address);
	if (!pte)
		return 0;

	set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
	__flush_tlb_one(address);
	return 1;
}

static void modulememcheck_show_all(void)
{
	struct modulememcheck_alloc_obj *pos;

	if (list_empty(&modulememcheck_allocations_head))
		return ;

	list_for_each_entry(pos, &modulememcheck_allocations_head, list) {
		if (0 == pos->type) {
			int i;
			unsigned long address = pos->page_address;
			for (i = 0; i < pos->pages; i++) {
				modulememcheck_show_addr(address);
				address += PAGE_SIZE;
			}
		}
	}
}

static void modulememcheck_hide_all(void)
{
	struct modulememcheck_alloc_obj *pos;

	if (list_empty(&modulememcheck_allocations_head))
		return ;

	list_for_each_entry(pos, &modulememcheck_allocations_head, list) {
		if (0 == pos->type) {
			int i;
			unsigned long address = pos->page_address;
			for (i = 0; i < pos->pages; i++) {
				modulememcheck_hide_addr(address);
				address += PAGE_SIZE;
			}
		}
	}
}

static long saved_regs_flags = 0;
static void modulememcheck_set_singlestep(struct pt_regs *regs)
{
//	long saved_regs_flags = __get_cpu_var(modulememcheck_regs_flags);

//	if (!(saved_regs_flags & X86_EFLAGS_TF))
	saved_regs_flags = regs->flags;
	if (saved_regs_flags & X86_EFLAGS_IF)
		regs->flags &= ~X86_EFLAGS_IF;
	if (!(saved_regs_flags & X86_EFLAGS_TF))
		regs->flags |= X86_EFLAGS_TF;
	return ;

/*
	if (!(regs->flags & X86_EFLAGS_TF))
		saved_regs_flags = regs->flags;

	regs->flags |= X86_EFLAGS_TF;
	regs->flags &= ~X86_EFLAGS_IF;
	return ;
	*/
}

static void modulememcheck_clear_singlestep(struct pt_regs *regs)
{
//	long saved_regs_flags = __get_cpu_var(modulememcheck_regs_flags);

	if (!(saved_regs_flags & X86_EFLAGS_TF))
		regs->flags &= ~X86_EFLAGS_TF;
	if (saved_regs_flags & X86_EFLAGS_IF)
		regs->flags |= X86_EFLAGS_IF;
	return ;

/*
	if (!(saved_regs_flags & X86_EFLAGS_TF))
		regs->flags &= ~X86_EFLAGS_TF;
	if (saved_regs_flags & X86_EFLAGS_IF)
		regs->flags |= X86_EFLAGS_IF;
	return ;
	*/
}

static int mmc_what_flag = 0;

bool modulememcheck_fault(struct pt_regs *regs, unsigned long address,
	unsigned long error_code)
{
	unsigned long ret;
//	unsigned long irq_flags;

	if (modulememcheck_enabled == MODULEMEMCHECK_DISABLED)
		return false;

	BUG_ON(!modulememcheck_pf_handler);

	BUG_ON(!regs);


	if (regs->flags & X86_VM_MASK)
		return false;
	if (regs->cs != __KERNEL_CS)
		return false;

	//printk("[MODULE MEM CHECK] : modulememcheck falut ! \n");
	
//	MMC_DEBUG("modulememcheck_fault : lock");
//	spin_lock_irqsave(&mmc_allocations_lock, irq_flags);
	modulememcheck_show_all();
	ret = modulememcheck_is_interest(address);
//	MMC_DEBUG("modulememcheck_fault : unlock");
//	spin_unlock_irqrestore(&mmc_allocations_lock, irq_flags);

	if (ret == 0) {
		modulememcheck_hide_all();
		return false;
	}
/*
	// make the pte present
	if (!modulememcheck_show_addr(address)) {	// pte is 0 
	//	MMC_DEBUG("modulememcheck_fault : show addr false");
		printk("modulememcheck_fault : show addr false\n");
		return false;
	}
*/
	hide_address = address;
	mmc_what_flag = 1;

//	printk(KERN_ALERT"[MMC]fault \n");
	if (ret > 1) {
		if ((*modulememcheck_pf_handler)(regs, address, error_code, ret))
//	printk(KERN_ALERT"[MMC]fault :  %lx\n", address);
			;//printk("[MMC]->modulememcheck_fault\n");
	}// else 

	// ret == 1
	// for single step
	modulememcheck_set_singlestep(regs);
	
	return true;
}

bool modulememcheck_trap(struct pt_regs *regs)
{
	if (modulememcheck_enabled == MODULEMEMCHECK_DISABLED)
		return false;
	if (mmc_what_flag == 0)
		return false;
//	printk(KERN_ALERT"[MMC]trap : \n");
	modulememcheck_hide_all();
//	modulememcheck_hide_addr(hide_address);
	mmc_what_flag = 0;
	modulememcheck_clear_singlestep(regs);
	return true;
}

/*
 *  add to list in Ascending order
 */
static bool modulememcheck_allocations_add(struct modulememcheck_alloc_obj *obj)
{
	struct modulememcheck_alloc_obj *pos;
	struct modulememcheck_alloc_obj *prev;

	if (list_empty(&modulememcheck_allocations_head)) {
		list_add(&obj->list, &modulememcheck_allocations_head);
		return true;
	}

	list_for_each_entry(pos, &modulememcheck_allocations_head, list) {
		if (obj->page_address < pos->page_address) 
			break;
	}
	prev = list_entry(pos->list.prev, struct modulememcheck_alloc_obj, list);
	
	// the "address + size < pos->page_address"
	// can deduce "page_address + pagesize * pages < pos->page_address"
	
	// add to the end	
	if (&pos->list == &modulememcheck_allocations_head) {
		if (obj->page_address < (prev->address + prev->size))
			return false;
		else {
			__list_add(&obj->list, &prev->list, &pos->list);
			return true;
		}
	}
	// add to the first
	if (&prev->list == &modulememcheck_allocations_head) {
		if ((obj->address + obj->size) > pos->page_address)
			return false;
		else {
			__list_add(&obj->list, &prev->list, &pos->list);
			return true;
		}
	}
	// add into the middle
	if (obj->page_address < (prev->address + prev->size) ||
			(obj->address + obj->size) > pos->page_address) 
		return false;
	__list_add(&obj->list, &prev->list, &pos->list);
	return true;
}

/*
 *  del from the allocations list
 */
static void modulememcheck_allocations_del(struct modulememcheck_alloc_obj *del_obj)
{
	list_del(&del_obj->list);
}

/*
 *  recovery the hide pages, delete objects, free the resource
 */
static void modulememcheck_allocations_remove(struct modulememcheck_alloc_obj *obj)
{
	if (!obj)
		return ;
	if (obj->type == 1) {	// 2M page
		if (!modulememcheck_show_addr(obj->address)) {
			printk(KERN_ALERT"[MMC] mmc_allocation_remove[large page] : pte is 0\n");
		}
	} else {
		int i;
		unsigned long address = obj->address;
		/* recovry all the pages related to the [address, address + size] */	
		for (i = 0; i < obj->pages; i++) {
			if (!modulememcheck_show_addr(address)) {
				printk(KERN_ALERT"[MMC] mmc_allocation_remove : pte is 0\n");
			}
			address += PAGE_SIZE;
		}
	}
	modulememcheck_allocations_del(obj);
	//kfree(obj);
	vfree(obj);
}

static void modulememcheck_allocations_clear(void)
{
	struct modulememcheck_alloc_obj *pos, *node;

	if (list_empty(&modulememcheck_allocations_head)) {
		return ;
	}

	list_for_each_entry_safe(pos, node, &modulememcheck_allocations_head, list) {
		modulememcheck_allocations_remove(pos);
	}
}

static struct modulememcheck_alloc_obj *modulememcheck_allocations_lookup(unsigned long address)
{
	struct modulememcheck_alloc_obj *pos;

	if (list_empty(&modulememcheck_allocations_head)) {
		return NULL;
	}

	list_for_each_entry(pos, &modulememcheck_allocations_head, list) {
		if (address == pos->address) {
			return pos;
		}
		if (address < pos->address) {
			break;
		}
	}
	return NULL;
}

bool modulememcheck_alloc(unsigned long address, unsigned long size)
{
	struct modulememcheck_alloc_obj *obj;
	int i;
	pte_t *pte;
	int level;
//	unsigned long irq_flags;
//	obj = (struct modulememcheck_alloc_obj *)kmalloc(sizeof(struct modulememcheck_alloc_obj), GFP_KERNEL);
	obj = (struct modulememcheck_alloc_obj *)vmalloc(sizeof(struct modulememcheck_alloc_obj));
	if (!obj) {
		printk("[MMC]->modulememcheck_alloc :not enough memory\n");
		return false;
	}
	obj->address = address;
	obj->size = size;

	pte = lookup_address(address, &level);
	// check whether the page is exist ?
	if (!(pte_val(*pte) | _PAGE_PRESENT)) {
		*(char *)address = '0';
	}
	

//	MMC_DEBUG("modulememcheck_alloc : lock");
//	spin_lock_irqsave(&mmc_allocations_lock, irq_flags);
	// is a 2M page ?
	if (2 == level)  {	// 2: PG_LEVEL_2M
		obj->type = 1;
		obj->page_address = address & HC_2M_PAGE_MASK;
		obj->pages = 1;
		if (!modulememcheck_allocations_add(obj)) {
			goto mmc_alloc_failed;
		}
		modulememcheck_hide_addr(address);
	} else {	// 1: PG_LEVEL_4K
		obj->type = 0;
		obj->page_address = address & PAGE_MASK;
	
		/* hide all the pages related to the [address, address + size] */	
		size = size + address - obj->page_address;
		obj->pages = (size / PAGE_SIZE) + ((size % PAGE_SIZE) ? 1 : 0);

//		printk(KERN_ALERT "[MMC]ALLOC: address 0x%.8lx, paddr 0x%.8lx, pages %d\n", 
//				obj->address, obj->page_address, obj->pages);

		if (!modulememcheck_allocations_add(obj)) {
			goto mmc_alloc_failed;
		}
		for (i = 0; i < obj->pages; i++) {
			modulememcheck_hide_addr(address);
			address += PAGE_SIZE;
		}
	}
//	MMC_DEBUG("modulememcheck_alloc : unlock");
	//spin_unlock_irqrestore(&mmc_allocations_lock, irq_flags);
	return true;
mmc_alloc_failed:
//	MMC_DEBUG("modulememcheck_alloc : unlock");
	//spin_unlock_irqrestore(&mmc_allocations_lock, irq_flags);
	vfree(obj);
	//kfree(obj);
	return false;
}
EXPORT_SYMBOL(modulememcheck_alloc);

void modulememcheck_free(unsigned long address_start)
{
	struct modulememcheck_alloc_obj *obj;
	unsigned long irq_flags;
//	MMC_DEBUG("modulememcheck_free : lock");
	//spin_lock_irqsave(&mmc_allocations_lock, irq_flags);
	obj = modulememcheck_allocations_lookup(address_start);
	modulememcheck_allocations_remove(obj);
//	MMC_DEBUG("modulememcheck_free : unlock");
//	spin_unlock_irqrestore(&mmc_allocations_lock, irq_flags);
}
EXPORT_SYMBOL(modulememcheck_free);

/* if have registered before or handler is NULL,  then failed */
bool register_modulememcheck_pf_handler(bool (*handler)(struct pt_regs *regs, unsigned long address, unsigned long error_code, unsigned long buffer_addr))
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
	unsigned long irq_flags;
	if (modulememcheck_enabled == MODULEMEMCHECK_ENABLED) {
		modulememcheck_enabled = MODULEMEMCHECK_DISABLED;
		modulememcheck_pf_handler = NULL;
	 
		// clear the allocations objs
//		MMC_DEBUG("unregister_modulememcheck_pf_handler : lock");
//		spin_lock_irqsave(&mmc_allocations_lock, irq_flags);
		modulememcheck_allocations_clear();
//		MMC_DEBUG("unregister_modulememcheck_pf_handler : lock");
//		spin_unlock_irqrestore(&mmc_allocations_lock, irq_flags);

		printk("[MMC] : unregistered!\n");
	}
}
EXPORT_SYMBOL(unregister_modulememcheck_pf_handler);
