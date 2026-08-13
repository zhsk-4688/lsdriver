#ifndef SHADOW_MEMORY_H
#define SHADOW_MEMORY_H

#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/esr.h>
#include <asm/ptrace.h>

#include "export_fun.h"
#include "inline_hook_frame.h"
#include "lsdriver_log.h"

static inline int linear_read_physical(phys_addr_t paddr, void *buffer, size_t size);

enum ls_shadow_state
{
    LS_SHADOW_STATE_ORIGINAL = 0,
    LS_SHADOW_STATE_SHADOW_X = 1,
};

struct ls_shadow_page
{
    struct list_head list;
    struct mm_struct *mm;
    uint64_t page_addr;
    pte_t orig_pte;
    unsigned long orig_pfn;
    struct page *shadow_page;
    unsigned long shadow_pfn;
    spinlock_t lock;
    atomic_t refs;
    bool dead;
    enum ls_shadow_state state;
};

static LIST_HEAD(g_ls_shadow_pages);
static DEFINE_SPINLOCK(g_ls_shadow_pages_lock);

static inline void ls_shadow_get(struct ls_shadow_page *page)
{
    atomic_inc(&page->refs);
}

static inline void ls_shadow_put(struct ls_shadow_page *page)
{
    if (!page) return;

    if (!atomic_dec_and_test(&page->refs)) return;

    if (page->mm) mmdrop(page->mm);
    if (page->shadow_page) __free_page(page->shadow_page);
    kfree(page);
}

static inline pteval_t ls_shadow_replace_pfn(pteval_t value, unsigned long pfn)
{
#ifdef PTE_ADDR_MASK
    value &= ~((pteval_t)PTE_ADDR_MASK);
#else
    value &= ~(((pteval_t)PAGE_MASK) & ~(pteval_t)0xfff);
#endif
    value |= ((pteval_t)pfn << PAGE_SHIFT);
    return value;
}

static inline pteval_t ls_shadow_make_original_pte(const struct ls_shadow_page *page)
{
    return pte_val(page->orig_pte);
}

static inline pteval_t ls_shadow_make_read_original_pte(const struct ls_shadow_page *page)
{
    pteval_t value = ls_shadow_replace_pfn(pte_val(page->orig_pte), page->orig_pfn);
#ifdef PTE_UXN
    value |= PTE_UXN;
#endif
    return value;
}

static inline pteval_t ls_shadow_make_exec_pte(const struct ls_shadow_page *page)
{
    pteval_t value = ls_shadow_replace_pfn(pte_val(page->orig_pte), page->shadow_pfn);
#ifdef PTE_USER
    value &= ~PTE_USER;
#endif
#ifdef PTE_WRITE
    value &= ~PTE_WRITE;
#endif
#ifdef PTE_RDONLY
    value |= PTE_RDONLY;
#endif
#ifdef PTE_DBM
    value &= ~PTE_DBM;
#endif
#ifdef PTE_UXN
    value &= ~PTE_UXN;
#endif
    return value;
}

static struct ls_shadow_page *ls_shadow_find_page(struct mm_struct *mm, uint64_t addr)
{
    struct ls_shadow_page *page;
    uint64_t page_addr = untagged_addr(addr) & PAGE_MASK;

    spin_lock(&g_ls_shadow_pages_lock);
    list_for_each_entry(page, &g_ls_shadow_pages, list)
    {
        if (page->dead) continue;
        if (page->mm != mm) continue;
        if (page->page_addr != page_addr) continue;
        ls_shadow_get(page);
        spin_unlock(&g_ls_shadow_pages_lock);
        return page;
    }
    spin_unlock(&g_ls_shadow_pages_lock);
    return NULL;
}

static void ls_shadow_unlink_page(struct ls_shadow_page *page)
{
    bool removed = false;

    if (!page) return;

    spin_lock(&g_ls_shadow_pages_lock);
    if (!page->dead)
    {
        page->dead = true;
        list_del_init(&page->list);
        removed = true;
    }
    spin_unlock(&g_ls_shadow_pages_lock);

    if (removed) ls_shadow_put(page);
}

static bool ls_shadow_mapping_is_live(const struct ls_shadow_page *page, struct mm_struct *mm)
{
    pte_t *ptep;
    pte_t current_pte;
    unsigned long pfn;

    if (!page || !mm) return false;

    ptep = get_user_pte(mm, page->page_addr);
    if (!ptep) return false;

    current_pte = READ_ONCE(*ptep);
    if (!pte_present(current_pte) || !pfn_valid(pte_pfn(current_pte))) return false;

    pfn = pte_pfn(current_pte);
    return pfn == page->orig_pfn || pfn == page->shadow_pfn;
}

static int ls_shadow_switch_to_original_locked(struct ls_shadow_page *page)
{
    int status;

    if (!page || page->dead) return -EINVAL;
    if (page->state == LS_SHADOW_STATE_ORIGINAL) return 0;

    status = write_user_pte_value(page->mm, page->page_addr, ls_shadow_make_read_original_pte(page));
    if (!status) page->state = LS_SHADOW_STATE_ORIGINAL;
    return status;
}

static int ls_shadow_switch_to_shadow_locked(struct ls_shadow_page *page)
{
    int status;

    if (!page || page->dead) return -EINVAL;
    if (page->state == LS_SHADOW_STATE_SHADOW_X) return 0;

    status = write_user_pte_value(page->mm, page->page_addr, ls_shadow_make_exec_pte(page));
    if (!status) page->state = LS_SHADOW_STATE_SHADOW_X;
    return status;
}

static void ls_shadow_release_page(struct ls_shadow_page *page, bool restore_original)
{
    if (!page) return;

    spin_lock(&page->lock);
    if (restore_original && !page->dead) write_user_pte_value(page->mm, page->page_addr, ls_shadow_make_original_pte(page));
    spin_unlock(&page->lock);

    ls_shadow_unlink_page(page);
    ls_shadow_put(page);
}

static void ls_shadow_release_mm(struct mm_struct *mm)
{
    struct ls_shadow_page *page;
    struct ls_shadow_page *next;
    LIST_HEAD(release_list);

    if (!mm) return;

    spin_lock(&g_ls_shadow_pages_lock);
    list_for_each_entry_safe(page, next, &g_ls_shadow_pages, list)
    {
        if (page->dead || page->mm != mm) continue;
        page->dead = true;
        list_move_tail(&page->list, &release_list);
    }
    spin_unlock(&g_ls_shadow_pages_lock);

    list_for_each_entry_safe(page, next, &release_list, list)
    {
        list_del_init(&page->list);
        spin_lock(&page->lock);
        write_user_pte_value(page->mm, page->page_addr, ls_shadow_make_original_pte(page));
        spin_unlock(&page->lock);
        ls_shadow_put(page);
    }
}

static void ls_shadow_release_all(void)
{
    struct ls_shadow_page *page;
    struct ls_shadow_page *next;
    LIST_HEAD(release_list);

    spin_lock(&g_ls_shadow_pages_lock);
    list_for_each_entry_safe(page, next, &g_ls_shadow_pages, list)
    {
        if (page->dead) continue;
        page->dead = true;
        list_move_tail(&page->list, &release_list);
    }
    spin_unlock(&g_ls_shadow_pages_lock);

    list_for_each_entry_safe(page, next, &release_list, list)
    {
        list_del_init(&page->list);
        spin_lock(&page->lock);
        write_user_pte_value(page->mm, page->page_addr, ls_shadow_make_original_pte(page));
        spin_unlock(&page->lock);
        ls_shadow_put(page);
    }
}

static int ls_shadow_build_page(struct mm_struct *mm, struct vm_area_struct *vma, uint64_t page_addr, struct ls_shadow_page **out_page)
{
    struct ls_shadow_page *page;
    struct ls_shadow_page *live;
    pte_t *ptep;
    pte_t orig_pte;
    void *src;

    if (!mm || !vma || !out_page) return -EINVAL;
    if (!(vma->vm_flags & VM_EXEC)) return -EACCES;

    live = ls_shadow_find_page(mm, page_addr);
    if (live)
    {
        *out_page = live;
        return 0;
    }

    page = kzalloc(sizeof(*page), GFP_KERNEL);
    if (!page) return -ENOMEM;

    page->shadow_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!page->shadow_page)
    {
        kfree(page);
        return -ENOMEM;
    }

    ptep = get_user_pte(mm, page_addr);
    if (!ptep)
    {
        __free_page(page->shadow_page);
        kfree(page);
        return -EFAULT;
    }

    orig_pte = READ_ONCE(*ptep);
    if (!pte_present(orig_pte) || !pfn_valid(pte_pfn(orig_pte)))
    {
        __free_page(page->shadow_page);
        kfree(page);
        return -EFAULT;
    }

    page->mm = mm;
    mmgrab(mm);
    page->page_addr = page_addr;
    page->orig_pte = orig_pte;
    page->orig_pfn = pte_pfn(orig_pte);
    page->shadow_pfn = page_to_pfn(page->shadow_page);
    page->state = LS_SHADOW_STATE_ORIGINAL;
    atomic_set(&page->refs, 2);
    INIT_LIST_HEAD(&page->list);
    spin_lock_init(&page->lock);

    src = page_address(pfn_to_page(page->orig_pfn));
    if (!src)
    {
        ls_shadow_put(page);
        ls_shadow_put(page);
        return -EFAULT;
    }

    __builtin_memcpy(page_address(page->shadow_page), src, PAGE_SIZE);

    spin_lock(&g_ls_shadow_pages_lock);
    live = NULL;
    list_for_each_entry(live, &g_ls_shadow_pages, list)
    {
        if (live->dead) continue;
        if (live->mm != mm) continue;
        if (live->page_addr != page_addr) continue;
        ls_shadow_get(live);
        spin_unlock(&g_ls_shadow_pages_lock);
        ls_shadow_put(page);
        ls_shadow_put(page);
        *out_page = live;
        return 0;
    }
    list_add_tail(&page->list, &g_ls_shadow_pages);
    spin_unlock(&g_ls_shadow_pages_lock);

    *out_page = page;
    return 0;
}

static int ls_shadow_write_exec(struct mm_struct *mm, struct vm_area_struct *vma, uint64_t addr, const void *buffer, size_t size)
{
    struct ls_shadow_page *page;
    void *shadow_kaddr;
    uint64_t page_addr = untagged_addr(addr) & PAGE_MASK;
    size_t offset = offset_in_page(addr);
    int status;

    if (!buffer || !size) return 0;

    status = ls_shadow_build_page(mm, vma, page_addr, &page);
    if (status) return status;

    spin_lock(&page->lock);
    if (page->dead || !ls_shadow_mapping_is_live(page, mm))
    {
        spin_unlock(&page->lock);
        ls_shadow_release_page(page, true);
        return -ESTALE;
    }

    shadow_kaddr = page_address(page->shadow_page);
    __builtin_memcpy((char *)shadow_kaddr + offset, buffer, size);
    arm64_sync_code_range_all_cpus(shadow_kaddr, PAGE_SIZE);
    status = ls_shadow_switch_to_shadow_locked(page);
    spin_unlock(&page->lock);

    ls_shadow_put(page);
    return status;
}

static int ls_shadow_read_original(struct mm_struct *mm, uint64_t addr, void *buffer, size_t size)
{
    struct ls_shadow_page *page;
    phys_addr_t paddr;
    int status;

    page = ls_shadow_find_page(mm, addr);
    if (!page) return 0;

    spin_lock(&page->lock);
    if (page->dead)
    {
        spin_unlock(&page->lock);
        ls_shadow_put(page);
        return -ESTALE;
    }
    paddr = PFN_PHYS(page->orig_pfn) + offset_in_page(addr);
    spin_unlock(&page->lock);

    status = linear_read_physical(paddr, buffer, size);
    ls_shadow_put(page);
    return status ? status : 1;
}

static inline int ls_shadow_fault_kind(unsigned long esr)
{
    if ((esr & ESR_ELx_FSC) != (ESR_ELx_FSC_PERM | ESR_ELx_FSC_LEVEL)) return 0;

    switch (ESR_ELx_EC(esr))
    {
        case ESR_ELx_EC_IABT_LOW:
            return 1;
        case ESR_ELx_EC_DABT_LOW:
            return (esr & ESR_ELx_WNR) ? 3 : 2;
        default:
            return 0;
    }
}

static int ls_shadow_mem_abort_hook_work(struct pt_regs *hook_regs)
{
    struct pt_regs *regs;
    struct ls_shadow_page *page;
    unsigned long far;
    unsigned long esr;
    uint64_t page_addr;
    int fault_kind;
    int status = 0;

    if (!hook_regs || !current->mm) return 0;

    far = untagged_addr(hook_regs->regs[0]);
    esr = hook_regs->regs[1];
    regs = (struct pt_regs *)hook_regs->regs[2];
    if (!regs) return 0;

    fault_kind = ls_shadow_fault_kind(esr);
    if (!fault_kind) return 0;

    page_addr = (fault_kind == 1) ? (untagged_addr(regs->pc) & PAGE_MASK) : (far & PAGE_MASK);
    page = ls_shadow_find_page(current->mm, page_addr);
    if (!page) return 0;
    if (!mmap_read_trylock(current->mm))
    {
        ls_shadow_put(page);
        return 0;
    }

    spin_lock(&page->lock);
    if (page->dead || !ls_shadow_mapping_is_live(page, current->mm))
    {
        spin_unlock(&page->lock);
        mmap_read_unlock(current->mm);
        ls_shadow_release_page(page, true);
        return 0;
    }

    if (fault_kind == 1 && page->state == LS_SHADOW_STATE_ORIGINAL) status = ls_shadow_switch_to_shadow_locked(page);
    if (fault_kind == 2 && page->state == LS_SHADOW_STATE_SHADOW_X) status = ls_shadow_switch_to_original_locked(page);
    spin_unlock(&page->lock);

    if (fault_kind == 3)
    {
        ls_shadow_release_page(page, true);
        mmap_read_unlock(current->mm);
        return 0;
    }

    mmap_read_unlock(current->mm);
    ls_shadow_put(page);
    return status ? 0 : 1;
}

static int ls_shadow_exit_mmap_hook_work(struct pt_regs *hook_regs)
{
    if (!hook_regs) return 0;
    ls_shadow_release_mm((struct mm_struct *)hook_regs->regs[0]);
    return 0;
}

static struct hook_entry ls_shadow_hooks[] = {
    HOOK_ENTRY("do_mem_abort", ls_shadow_mem_abort_hook_work),
    HOOK_ENTRY("exit_mmap", ls_shadow_exit_mmap_hook_work),
};

static int ls_shadow_init(void)
{
    return inline_hook_install_count(ls_shadow_hooks, ARRAY_SIZE(ls_shadow_hooks));
}

#endif
