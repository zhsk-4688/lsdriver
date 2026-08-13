/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * W^X Shadow Memory 无痕 hook —— 移植自 wxshadow KPM 模块 (mkpms/kpms/wxshadow)
 *
 * 原理：在用户进程代码页上创建"影子页"，影子页里写入 BRK 断点或自定义 patch，
 *       进程读取时映射到原始页 (r--)，执行时映射到影子页 (--x)。
 *       这样内存完整性校验读到的永远是原始代码，hook 痕迹不留在被监控页上。
 *
 * 页面状态机：
 *   NONE -> SHADOW_X(--x) <-> ORIGINAL(r--) <-> STEPPING(r-x)
 *                       \-> DORMANT (hook 退休，保留影子页)
 *
 * 与 KernelPatch 版 wxshadow 的差异（本文件是 LKM 实现）：
 *   1. 删除 KP 框架依赖 (kpmodule.h/hook.h/ksyms.h/...)，全部改用标准内核 API
 *      + lsdriver 自身的 export_fun.h / inline_hook_frame.h。
 *   2. 用户态接口保持 prctl (0x5758000x)，通过 inline hook 接管
 *      __arm64_sys_prctl / __se_sys_prctl，wxshadow_client 可零改动使用。
 *   3. 内核符号：已导出符号直接链接；未导出符号 (__split_huge_pmd、
 *      user_enable_single_step、user_disable_single_step、kick_all_cpus_sync)
 *      用 generic_kallsyms_lookup_name + KCALL_n 宏调用。
 *   4. KP 的 before/after 成对 hook 在 lsdriver 框架里只有 before 型 work_fn：
 *      - follow_page_pte (GUP 隐藏)：在 before 里把 PTE 切回原页并广播刷 TLB、
 *        状态置回 ORIGINAL，后续取指故障会自动把映射切回影子页。
 *      - dup_mmap (fork 保护)：在 before 里暂停父进程的影子映射（状态切 ORIGINAL），
 *        恢复由取指故障路径完成（见 wxshadow_handle_exec_fault 里 fork_paused 处理）。
 *   5. 无 KP 卸载语义：去掉 wx_in_flight 计数 / KPM_INIT/EXIT 宏，
 *      hook 在 lsdriver_init 时安装，随模块常驻。
 *   6. 锁：全局锁统一 spin_lock_irqsave（BRK/step/fault 异常上下文安全），
 *      逐页 pte_lock 保留自旋原子锁设计。
 */

#ifndef _LSDRIVER_WXSHADOW_HOOK_H_
#define _LSDRIVER_WXSHADOW_HOOK_H_

#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rculist.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <asm/pgtable-prot.h>
#include <asm/barrier.h>

#include "io_struct.h"
#include "export_fun.h"
#include "inline_hook_frame.h"
#include "lsdriver_log.h"

/* ========== 常量 ========== */

/* prctl 命令字（与 wxshadow KPM 版完全一致，客户端零改动） */
#define PR_WXSHADOW_SET_BP 0x57580001      /* WX + 1: 设置隐藏断点 */
#define PR_WXSHADOW_SET_REG 0x57580002     /* WX + 2: 配置断点命中时的寄存器修改 */
#define PR_WXSHADOW_DEL_BP 0x57580003      /* WX + 3: 删除断点 */
#define PR_WXSHADOW_SET_TLB_MODE 0x57580004 /* WX + 4: 设置 TLB flush 模式 */
#define PR_WXSHADOW_GET_TLB_MODE 0x57580005 /* WX + 5: 获取 TLB flush 模式 */
#define PR_WXSHADOW_PATCH 0x57580006       /* WX + 6: 自定义 patch（写入影子页） */
#define PR_WXSHADOW_RELEASE 0x57580008     /* WX + 8: 释放 shadow，恢复原始页 */

/* TLB flush 模式（保留兼容；本实现统一走 lsdriver 广播刷 TLB 原语） */
enum wxshadow_tlb_mode
{
    WX_TLB_MODE_AUTO = 0,
    WX_TLB_MODE_PRECISE,
    WX_TLB_MODE_BROADCAST,
    WX_TLB_MODE_FULL,
};

/* BRK immediate 与指令编码 */
#define WXSHADOW_BRK_IMM 0x007
#define AARCH64_BREAK_MON 0xd4200000
#define WXSHADOW_BRK_INSN (AARCH64_BREAK_MON | (WXSHADOW_BRK_IMM << 5))
#define AARCH64_INSN_SIZE 4

/* 页面状态 */
enum wxshadow_state
{
    WX_STATE_NONE = 0,
    WX_STATE_ORIGINAL,   /* VA 映射到原始页 (r--) */
    WX_STATE_SHADOW_X,   /* VA 映射到影子页 (--x) */
    WX_STATE_STEPPING,   /* 正在单步执行原始指令 (r-x) */
    WX_STATE_DORMANT,    /* hook 退休；VA 恢复原始页，影子页保留 */
};

/* 每页断点/patch 容量 */
#define WXSHADOW_MAX_REG_MODS 4
#define WXSHADOW_MAX_BPS_PER_PAGE 128
#define WXSHADOW_MAX_PATCHES_PER_PAGE 128
#define WXSHADOW_DIRTY_WORD_BITS (sizeof(unsigned long) * 8)
#define WXSHADOW_DIRTY_BITMAP_WORDS ((PAGE_SIZE + WXSHADOW_DIRTY_WORD_BITS - 1) / WXSHADOW_DIRTY_WORD_BITS)

/* BRK/step 处理返回码 */
#define DBG_HOOK_HANDLED 0
#define DBG_HOOK_ERROR 1

/* PTE 位（若内核头文件已定义则复用） */
#ifndef PTE_VALID
#define PTE_VALID (1UL << 0)
#endif
#ifndef PTE_TYPE_PAGE
#define PTE_TYPE_PAGE (3UL << 0)
#endif
#ifndef PTE_USER
#define PTE_USER (1UL << 6)
#endif
#ifndef PTE_RDONLY
#define PTE_RDONLY (1UL << 7)
#endif
#ifndef PTE_SHARED
#define PTE_SHARED (3UL << 8)
#endif
#ifndef PTE_AF
#define PTE_AF (1UL << 10)
#endif
#ifndef PTE_NG
#define PTE_NG (1UL << 11)
#endif
#ifndef PTE_UXN
#define PTE_UXN (1UL << 54)
#endif
#ifndef PTE_WRITE
#define PTE_WRITE (1UL << 51) /* DBM */
#endif

/* PTE 中 PFN 位域 */
#define WXSHADOW_PTE_PFN_MASK 0x0000FFFFFFFFF000UL

/* ========== 数据结构 ========== */

/* 单个断点的寄存器修改条目 */
struct wxshadow_reg_mod
{
    u8 reg_idx;  /* 0-30: x0-x30, 31: sp */
    bool enabled;
    u64 value;
};

/* 单个断点 */
struct wxshadow_bp
{
    unsigned long addr;
    bool active;
    u64 serial; /* 影子页上的写入顺序号 */
    struct wxshadow_reg_mod reg_mods[WXSHADOW_MAX_REG_MODS];
    int nr_reg_mods;
};

/* 自定义 patch 记录 */
struct wxshadow_patch
{
    u16 offset;
    u16 len;
    bool active;
    u64 serial;
    void *data; /* 补丁字节 */
};

/* 每个被跟踪页的影子信息 */
struct wxshadow_page
{
    struct list_head list; /* 挂到全局 page_list */
    struct mm_struct *mm;  /* 所属进程 mm（不持引用，靠 exit_mmap hook 清理） */
    unsigned long page_addr;

    unsigned long pfn_original;  /* 原始页 PFN */
    pteval_t pte_original;       /* 原始用户 PTE 快照 */
    unsigned long pfn_shadow;    /* 影子页 PFN */
    void *shadow_page;           /* 影子页内核 VA（free 用） */
    enum wxshadow_state state;
    struct task_struct *stepping_task; /* 正在单步的任务 */
    int brk_in_flight;                 /* trap 与 STEPPING 之间的在途 BRK 数 */

    /* 生命周期字段（global_lock 保护）：
     *   refcount: 在 page_list 里时至少为 1（list 的引用）；find_page/find_by_addr
     *             调用者拿到引用后用完必须 wxshadow_page_put()，归零时 kfree。
     *   dead: 从 page_list 摘除后置位；拿到引用后的 handler 必须检查并跳过
     *         切影子页操作。
     *   release_pending: 任务处于 STEPPING 时收到 teardown；页面留在 list 里等
     *                     step handler 完成收尾。
     *   logical_release_pending: 用户释放想退休 hook 但不想拆页；step handler
     *                             在原始指令执行完后把页切到 DORMANT。
     *   fork_paused: copy_process 克隆父 mm 期间置位；父 PTE 临时恢复原页，
     *                子进程不会继承影子 PFN；fork 返回后父映射由取指故障
     *                路径切回影子页。
     */
    int refcount;
    bool dead;
    bool release_pending;
    bool logical_release_pending;
    bool fork_paused;
    atomic_t pte_lock; /* 串行化本页 PTE 改写 */

    /* 断点信息 */
    struct wxshadow_bp bps[WXSHADOW_MAX_BPS_PER_PAGE];
    int nr_bps;
    struct wxshadow_patch patches[WXSHADOW_MAX_PATCHES_PER_PAGE];
    int nr_patches;
    u64 next_mod_serial;
    unsigned long bp_dirty[WXSHADOW_DIRTY_BITMAP_WORDS];
    unsigned long patch_dirty[WXSHADOW_DIRTY_BITMAP_WORDS];
};

/* ========== 全局状态 ========== */

static DEFINE_SPINLOCK(wxshadow_global_lock);
static LIST_HEAD(wxshadow_page_list);

static int wxshadow_tlb_flush_mode = WX_TLB_MODE_PRECISE;

/* ========== 非导出内核符号（kallsyms + KCALL 调用） ========== */

static void (*wxshadow_fn___split_huge_pmd)(void *vma, void *pmd, unsigned long address,
                                            bool freeze, void *page);
static void (*wxshadow_fn_user_enable_single_step)(void *task);
static void (*wxshadow_fn_user_disable_single_step)(void *task);
static void (*wxshadow_fn_kick_all_cpus_sync)(void);
static long (*wxshadow_fn_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);

static void wxshadow_resolve_symbols(void)
{
    wxshadow_fn___split_huge_pmd = (void *)generic_kallsyms_lookup_name("__split_huge_pmd");
    wxshadow_fn_user_enable_single_step = (void *)generic_kallsyms_lookup_name("user_enable_single_step");
    wxshadow_fn_user_disable_single_step = (void *)generic_kallsyms_lookup_name("user_disable_single_step");
    wxshadow_fn_kick_all_cpus_sync = (void *)generic_kallsyms_lookup_name("kick_all_cpus_sync");
    wxshadow_fn_copy_from_kernel_nofault = (void *)generic_kallsyms_lookup_name("copy_from_kernel_nofault");
    if (!wxshadow_fn_copy_from_kernel_nofault)
        wxshadow_fn_copy_from_kernel_nofault = (void *)generic_kallsyms_lookup_name("probe_kernel_read");

    if (!wxshadow_fn_user_enable_single_step || !wxshadow_fn_user_disable_single_step)
        ls_log_always_tag("wxshadow", "user_enable/disable_single_step 未找到，无痕断点单步将不可用\n");
    if (!wxshadow_fn___split_huge_pmd)
        ls_log_always_tag("wxshadow", "__split_huge_pmd 未找到，THP 页无法下断\n");
}

/* ========== 基础辅助 ========== */

static inline bool wxshadow_is_kva(unsigned long addr)
{
    return (addr >> 48) == 0xffff;
}

/* 安全读内核内存：优先 copy_from_kernel_nofault，退化为直接解引用 */
static inline bool wxshadow_safe_read_u64(unsigned long addr, u64 *out)
{
    if (!wxshadow_is_kva(addr))
        return false;

    if (wxshadow_fn_copy_from_kernel_nofault)
        return KCALL_3(wxshadow_fn_copy_from_kernel_nofault, long, out, (const void *)addr, sizeof(*out)) == 0;

    *out = *(u64 *)addr;
    return true;
}

static inline bool wxshadow_safe_read_ptr(unsigned long addr, void **out)
{
    return wxshadow_safe_read_u64(addr, (u64 *)out);
}

/* PFN -> 内核线性映射 VA */
static inline void *wxshadow_pfn_to_kaddr(unsigned long pfn)
{
    struct page *p = pfn_to_page(pfn);
    if (!p)
        return NULL;
    return page_address(p);
}

/* 逐页 PTE 改写自旋锁（原子自旋，异常上下文安全） */
static inline void wxshadow_page_pte_lock(struct wxshadow_page *page)
{
    while (atomic_cmpxchg(&page->pte_lock, 0, 1) != 0)
        cpu_relax();
}

static inline void wxshadow_page_pte_unlock(struct wxshadow_page *page)
{
    atomic_set(&page->pte_lock, 0);
}

/* 读用户 PTE 值（锁无关，lsdriver 风格） */
static inline int wxshadow_read_pte(struct mm_struct *mm, unsigned long addr, pteval_t *out)
{
    pte_t *ptep = get_user_pte(mm, addr);
    if (!ptep)
        return -EFAULT;
    *out = pte_val(READ_ONCE(*ptep));
    return 0;
}

/* 写用户 PTE 值并广播刷 TLB（复用 lsdriver 原语） */
static inline int wxshadow_write_pte(struct mm_struct *mm, unsigned long addr, pteval_t new_pte)
{
    return write_user_pte_value(mm, addr, new_pte);
}

/* 同步影子页新机器码：dc cvau 到 PoU + ic ialluis 全局失效 */
static inline void wxshadow_sync_shadow_code(unsigned long kva, unsigned long size)
{
    arm64_sync_code_range_all_cpus((const void *)kva, size);
}

/* 全局 icache 失效（PTE 切换后使用） */
static inline void wxshadow_invalidate_icache_all(void)
{
    __arm64_invalidate_icache_all_cpus();
}

/*
 * 同步执行中的影子页（把 PTE 恢复原页后，确保所有 CPU 都不再从影子页取指）。
 * 找不到 kick_all_cpus_sync 时退化为内存屏障 + 提示。
 */
static inline void wxshadow_sync_shadow_exec_zero(struct wxshadow_page *page, const char *reason)
{
    if (!wxshadow_fn_kick_all_cpus_sync)
    {
        ls_log_always_tag("wxshadow", "[%s] kick_all_cpus_sync 不可用 addr=%lx\n",
                          reason, page ? page->page_addr : 0UL);
        asm volatile("dsb ish" : : : "memory");
        return;
    }
    KCALL_0(wxshadow_fn_kick_all_cpus_sync, void);
}

/* ========== PTE 构造（与 wxshadow 位语义一致） ========== */

/* 替换 PTE 中的 PFN，保留原有属性位 */
static inline pteval_t wxshadow_replace_pte_pfn(pteval_t entry, unsigned long pfn)
{
    entry &= ~WXSHADOW_PTE_PFN_MASK;
    entry |= (pfn << PAGE_SHIFT) & WXSHADOW_PTE_PFN_MASK;
    entry |= PTE_VALID | PTE_TYPE_PAGE;
    return entry;
}

static inline pteval_t wxshadow_get_original_pte_template(struct wxshadow_page *page)
{
    if (page && page->pte_original)
        return page->pte_original;
    if (page && page->pfn_original)
        return wxshadow_replace_pte_pfn(0, page->pfn_original) | PTE_USER | PTE_RDONLY;
    return 0;
}

/* teardown/逻辑释放时的完整恢复 PTE：原样还原 */
static inline pteval_t wxshadow_build_restore_original_pte(struct wxshadow_page *page)
{
    return wxshadow_get_original_pte_template(page);
}

/* 隐藏原页 (r-- + UXN)：可读不可执行 */
static inline pteval_t wxshadow_build_hidden_original_pte(struct wxshadow_page *page)
{
    pteval_t entry = wxshadow_get_original_pte_template(page);

    if (!entry || !page || !page->pfn_original)
        return 0;

    entry = wxshadow_replace_pte_pfn(entry, page->pfn_original);
    entry |= PTE_USER | PTE_RDONLY | PTE_UXN;
    entry &= ~PTE_WRITE;
    return entry;
}

/* 单步原页 (r-x)：可读可执行 */
static inline pteval_t wxshadow_build_stepping_original_pte(struct wxshadow_page *page)
{
    pteval_t entry = wxshadow_get_original_pte_template(page);

    if (!entry || !page || !page->pfn_original)
        return 0;

    entry = wxshadow_replace_pte_pfn(entry, page->pfn_original);
    entry |= PTE_USER | PTE_RDONLY;
    entry &= ~PTE_UXN;
    entry &= ~PTE_WRITE;
    return entry;
}

/* 影子页 (--x)：可执行、EL0 不可读不可写（AP=00, UXN=0） */
static inline pteval_t wxshadow_build_shadow_exec_pte(struct wxshadow_page *page)
{
    pteval_t entry = wxshadow_get_original_pte_template(page);

    if (!entry || !page || !page->pfn_shadow)
        return 0;

    entry = wxshadow_replace_pte_pfn(entry, page->pfn_shadow);
    entry |= PTE_AF | PTE_SHARED | PTE_NG;
    entry &= ~PTE_RDONLY; /* AP[2]=0 */
    entry &= ~PTE_USER;   /* AP[1]=0 -> AP=00: EL0 无读写 */
    entry &= ~PTE_UXN;    /* 可执行 */
    entry &= ~PTE_WRITE;
    return entry;
}

/* ========== THP 2MB block 拆分 ========== */

/*
 * 目标地址所在 PMD 是 block(2MB) 映射时，用 __split_huge_pmd 拆成普通页。
 * 调用时机在进程上下文（prctl 派发），与 wxshadow 一致不加 mmap 锁。
 */
static int wxshadow_try_split_pmd(struct mm_struct *mm, struct vm_area_struct *vma,
                                  unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pmd_t pmd_val;

    if (!mm || !vma)
        return 0;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud) || pud_leaf(*pud)) /* 1G block 不处理 */
        return 0;
    pmd = pmd_offset(pud, addr);
    pmd_val = READ_ONCE(*pmd);
    if (pmd_none(pmd_val) || !pmd_leaf(pmd_val))
        return 0; /* 普通页或空，无需拆分 */

    if (!wxshadow_fn___split_huge_pmd)
    {
        ls_log_always_tag("wxshadow", "addr %lx 位于 PMD block 但 __split_huge_pmd 不可用\n", addr);
        return -ENOSYS;
    }

    KCALL_5(wxshadow_fn___split_huge_pmd, void, vma, pmd, addr & PMD_MASK, false, NULL);

    pmd_val = READ_ONCE(*pmd);
    if (pmd_leaf(pmd_val))
    {
        ls_log_always_tag("wxshadow", "PMD block 拆分失败 addr=%lx\n", addr);
        return -1;
    }

    return 0;
}

/* ========== 引用计数 / 页面生命周期 ========== */

/*
 * wxshadow_page_put - 释放一个引用。
 * refcount 归零时 kfree 结构体，并释放影子页与 patch 数据。
 * 内部自取 global_lock，任何上下文可调用。
 */
static void wxshadow_page_put(struct wxshadow_page *page)
{
    int should_free;
    unsigned long shadow_vaddr = 0;
    void *patch_data[WXSHADOW_MAX_PATCHES_PER_PAGE];
    int nr_patch_data = 0;
    int i;
    unsigned long flags;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    should_free = (--page->refcount == 0);
    if (should_free)
    {
        if (page->shadow_page)
        {
            shadow_vaddr = (unsigned long)page->shadow_page;
            page->shadow_page = NULL;
        }
        for (i = 0; i < page->nr_patches; i++)
        {
            if (!page->patches[i].data)
                continue;
            patch_data[nr_patch_data++] = page->patches[i].data;
            page->patches[i].data = NULL;
        }
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (should_free)
    {
        for (i = 0; i < nr_patch_data; i++)
            kfree(patch_data[i]);
        if (shadow_vaddr)
            free_pages(shadow_vaddr, 0);
        kfree(page);
    }
}

/*
 * 按 mm+地址找页。返回带引用计数的页（调用者必须 wxshadow_page_put）。
 * 找不到返回 NULL（不取引用）。
 */
static struct wxshadow_page *wxshadow_find_page(struct mm_struct *mm, unsigned long addr)
{
    struct list_head *pos;
    struct wxshadow_page *page;
    unsigned long target_addr = addr & PAGE_MASK;
    unsigned long flags;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    list_for_each(pos, &wxshadow_page_list)
    {
        page = container_of(pos, struct wxshadow_page, list);
        if (page->mm == mm && page->page_addr == target_addr)
        {
            page->refcount++;
            spin_unlock_irqrestore(&wxshadow_global_lock, flags);
            return page;
        }
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    return NULL;
}

static struct wxshadow_page *wxshadow_create_page(struct mm_struct *mm, unsigned long page_addr)
{
    struct wxshadow_page *page;
    unsigned long flags;

    page = kzalloc(sizeof(*page), GFP_KERNEL);
    if (!page)
        return NULL;

    page->mm = mm;
    page->page_addr = page_addr;
    page->state = WX_STATE_NONE;
    page->refcount = 2; /* list 引用 + 调用者引用 */
    page->dead = false;
    atomic_set(&page->pte_lock, 0);
    INIT_LIST_HEAD(&page->list);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    list_add(&page->list, &wxshadow_page_list);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    ls_log_always_tag("wxshadow", "created page for mm=%px addr=%lx\n", mm, page_addr);
    return page;
}

/*
 * 从 list 摘除并标记 dead。调用者必须另行用 wxshadow_page_put 释放自己的引用。
 * 影子页内存在最后一个引用释放时回收。
 */
static void wxshadow_free_page(struct wxshadow_page *page)
{
    unsigned long flags;

    if (!page)
        return;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    page->dead = true;
    list_del_init(&page->list);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    wxshadow_page_put(page); /* 释放 list 的引用 */
}

static struct wxshadow_bp *wxshadow_find_bp(struct wxshadow_page *page_info, unsigned long pc)
{
    int i;
    for (i = 0; i < page_info->nr_bps; i++)
    {
        if (page_info->bps[i].active && page_info->bps[i].addr == pc)
            return &page_info->bps[i];
    }
    return NULL;
}

/* ========== 脏位图跟踪 ========== */

static void wxshadow_bitmap_set_range(unsigned long *bitmap, unsigned long offset, unsigned long len)
{
    unsigned long i;

    if (!bitmap || offset >= PAGE_SIZE || len == 0)
        return;
    if (offset + len > PAGE_SIZE)
        len = PAGE_SIZE - offset;

    for (i = offset; i < offset + len; i++)
    {
        unsigned long word = i / WXSHADOW_DIRTY_WORD_BITS;
        unsigned long bit = i % WXSHADOW_DIRTY_WORD_BITS;
        bitmap[word] |= (1UL << bit);
    }
}

static bool wxshadow_bitmap_test(const unsigned long *bitmap, unsigned long offset)
{
    unsigned long word;
    unsigned long bit;

    if (!bitmap || offset >= PAGE_SIZE)
        return false;

    word = offset / WXSHADOW_DIRTY_WORD_BITS;
    bit = offset % WXSHADOW_DIRTY_WORD_BITS;
    return !!(bitmap[word] & (1UL << bit));
}

static void wxshadow_trim_inactive_tail_locked(struct wxshadow_page *page)
{
    while (page->nr_bps > 0 && !page->bps[page->nr_bps - 1].active)
        page->nr_bps--;

    while (page->nr_patches > 0 &&
           !page->patches[page->nr_patches - 1].active &&
           !page->patches[page->nr_patches - 1].data)
        page->nr_patches--;
}

static void wxshadow_rebuild_dirty_tracking_locked(struct wxshadow_page *page)
{
    int i;

    if (!page)
        return;

    memset(page->bp_dirty, 0, sizeof(page->bp_dirty));
    memset(page->patch_dirty, 0, sizeof(page->patch_dirty));

    for (i = 0; i < page->nr_bps; i++)
    {
        struct wxshadow_bp *bp = &page->bps[i];

        if (!bp->active)
            continue;
        wxshadow_bitmap_set_range(page->bp_dirty, bp->addr & ~PAGE_MASK, AARCH64_INSN_SIZE);
    }

    for (i = 0; i < page->nr_patches; i++)
    {
        struct wxshadow_patch *patch = &page->patches[i];

        if (!patch->active || patch->len == 0)
            continue;
        wxshadow_bitmap_set_range(page->patch_dirty, patch->offset, patch->len);
    }
}

static void wxshadow_mark_patch_dirty(struct wxshadow_page *page, unsigned long offset, unsigned long len)
{
    unsigned long flags;

    if (!page)
        return;
    (void)offset;
    (void)len;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    wxshadow_rebuild_dirty_tracking_locked(page);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
}

static void wxshadow_mark_bp_dirty(struct wxshadow_page *page, unsigned long offset)
{
    unsigned long flags;

    if (!page)
        return;
    (void)offset;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    wxshadow_rebuild_dirty_tracking_locked(page);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
}

static void wxshadow_sync_page_tracking(struct wxshadow_page *page)
{
    unsigned long flags;

    if (!page)
        return;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    wxshadow_trim_inactive_tail_locked(page);
    wxshadow_rebuild_dirty_tracking_locked(page);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
}

static void wxshadow_clear_page_tracking(struct wxshadow_page *page)
{
    void *patch_data[WXSHADOW_MAX_PATCHES_PER_PAGE];
    int nr_patch_data = 0;
    int i;
    unsigned long flags;

    if (!page)
        return;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    for (i = 0; i < page->nr_patches; i++)
    {
        if (!page->patches[i].data)
            continue;
        patch_data[nr_patch_data++] = page->patches[i].data;
        page->patches[i].data = NULL;
    }
    page->nr_bps = 0;
    page->nr_patches = 0;
    page->next_mod_serial = 0;
    memset(page->bps, 0, sizeof(page->bps));
    memset(page->patches, 0, sizeof(page->patches));
    memset(page->bp_dirty, 0, sizeof(page->bp_dirty));
    memset(page->patch_dirty, 0, sizeof(page->patch_dirty));
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    for (i = 0; i < nr_patch_data; i++)
        kfree(patch_data[i]);
}

/* 把脏字节从原始页复制回影子页（逻辑释放后保留干净影子页） */
static int wxshadow_restore_shadow_ranges(struct wxshadow_page *page)
{
    unsigned long bp_dirty[WXSHADOW_DIRTY_BITMAP_WORDS];
    unsigned long patch_dirty[WXSHADOW_DIRTY_BITMAP_WORDS];
    unsigned long original_pfn;
    unsigned long shadow_vaddr;
    unsigned long start;
    unsigned long end;
    unsigned long restored = 0;
    unsigned long page_addr;
    const char *original_kaddr;
    unsigned long flags;

    if (!page)
        return -EINVAL;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (!page->shadow_page || !page->pfn_original)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        return -EFAULT;
    }
    memcpy(bp_dirty, page->bp_dirty, sizeof(bp_dirty));
    memcpy(patch_dirty, page->patch_dirty, sizeof(patch_dirty));
    original_pfn = page->pfn_original;
    shadow_vaddr = (unsigned long)page->shadow_page;
    page_addr = page->page_addr;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    original_kaddr = (const char *)wxshadow_pfn_to_kaddr(original_pfn);
    if (!wxshadow_is_kva((unsigned long)original_kaddr))
        return -EFAULT;

    start = 0;
    while (start < PAGE_SIZE)
    {
        bool dirty = wxshadow_bitmap_test(bp_dirty, start) ||
                     wxshadow_bitmap_test(patch_dirty, start);

        if (!dirty)
        {
            start++;
            continue;
        }

        end = start + 1;
        while (end < PAGE_SIZE)
        {
            bool more_dirty = wxshadow_bitmap_test(bp_dirty, end) ||
                              wxshadow_bitmap_test(patch_dirty, end);
            if (!more_dirty)
                break;
            end++;
        }

        memcpy((void *)(shadow_vaddr + start), original_kaddr + start, end - start);
        restored += end - start;
        start = end;
    }

    if (restored)
        wxshadow_sync_shadow_code(shadow_vaddr, PAGE_SIZE);

    ls_log_always_tag("wxshadow", "[logical_release] restored %lu bytes at addr=%lx\n",
                      restored, page_addr);
    return 0;
}

/* ========== 映射校验 ========== */

static int wxshadow_validate_page_mapping(struct mm_struct *mm, struct vm_area_struct *vma,
                                          struct wxshadow_page *page_info, unsigned long page_addr)
{
    pteval_t pte_val;
    unsigned long current_pfn;

    if (!vma || vma->vm_start > page_addr || vma->vm_end <= page_addr)
    {
        ls_log_always_tag("wxshadow", "validate_mapping: VMA invalid for addr %lx\n", page_addr);
        return 0;
    }

    if (wxshadow_read_pte(mm, page_addr, &pte_val) < 0)
    {
        ls_log_always_tag("wxshadow", "validate_mapping: PTE not found for addr %lx\n", page_addr);
        return 0;
    }

    if (!(pte_val & PTE_VALID))
    {
        ls_log_always_tag("wxshadow", "validate_mapping: PTE invalid for addr %lx\n", page_addr);
        return 0;
    }

    current_pfn = (pte_val & WXSHADOW_PTE_PFN_MASK) >> PAGE_SHIFT;

    if (page_info->pfn_shadow && current_pfn == page_info->pfn_shadow)
        return 1;

    if (page_info->pfn_original && current_pfn == page_info->pfn_original)
    {
        if (page_info->state == WX_STATE_ORIGINAL ||
            page_info->state == WX_STATE_STEPPING ||
            page_info->state == WX_STATE_SHADOW_X ||
            page_info->state == WX_STATE_DORMANT)
            return 1;
    }

    ls_log_always_tag("wxshadow", "validate_mapping: PFN mismatch for addr %lx: current=%lx, orig=%lx, shadow=%lx, state=%d\n",
                      page_addr, current_pfn, page_info->pfn_original,
                      page_info->pfn_shadow, page_info->state);
    return 0;
}

/* ========== PTE 状态切换（影子/原始/单步） ========== */

static int wxshadow_page_activate_shadow_locked(struct wxshadow_page *page,
                                                struct vm_area_struct *vma,
                                                unsigned long addr)
{
    pteval_t entry;
    unsigned long flags;

    (void)vma;
    (void)addr;

    if (!page)
        return -1;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page->dead || page->release_pending ||
        page->logical_release_pending || !page->pfn_shadow)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        return -2;
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    entry = wxshadow_build_shadow_exec_pte(page);
    if (!entry)
        return -2;

    if (wxshadow_write_pte(page->mm, addr, entry) < 0)
        return -1;

    wxshadow_invalidate_icache_all();

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (!page->dead)
        page->state = WX_STATE_SHADOW_X;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    return 0;
}

static int wxshadow_page_activate_shadow(struct wxshadow_page *page,
                                         struct vm_area_struct *vma,
                                         unsigned long addr)
{
    int ret;

    if (!page)
        return -1;

    wxshadow_page_pte_lock(page);
    ret = wxshadow_page_activate_shadow_locked(page, vma, addr);
    wxshadow_page_pte_unlock(page);
    return ret;
}

/* SHADOW_X -> ORIGINAL (r--)：读取隐藏 */
static int wxshadow_page_enter_original(struct wxshadow_page *page,
                                        struct vm_area_struct *vma,
                                        unsigned long addr)
{
    int ret;
    pteval_t entry;
    unsigned long flags;

    (void)vma;
    (void)addr;

    if (!page)
        return -1;

    wxshadow_page_pte_lock(page);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page->dead || page->release_pending ||
        page->logical_release_pending ||
        page->state != WX_STATE_SHADOW_X ||
        !page->pfn_original)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return -2;
    }
    entry = wxshadow_build_hidden_original_pte(page);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (!entry)
    {
        wxshadow_page_pte_unlock(page);
        return -2;
    }

    ret = wxshadow_write_pte(page->mm, addr, entry);
    if (ret == 0)
    {
        spin_lock_irqsave(&wxshadow_global_lock, flags);
        if (!page->dead)
            page->state = WX_STATE_ORIGINAL;
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    }

    wxshadow_page_pte_unlock(page);
    return ret;
}

/* ORIGINAL -> SHADOW_X：取指故障后切回影子页 */
static int wxshadow_page_resume_shadow(struct wxshadow_page *page,
                                       struct vm_area_struct *vma,
                                       unsigned long addr)
{
    int ret;
    pteval_t entry;
    unsigned long flags;

    (void)vma;
    (void)addr;

    if (!page)
        return -1;

    wxshadow_page_pte_lock(page);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page->dead || page->release_pending ||
        page->logical_release_pending ||
        page->state != WX_STATE_ORIGINAL ||
        !page->pfn_shadow)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return -2;
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    entry = wxshadow_build_shadow_exec_pte(page);
    if (!entry)
    {
        wxshadow_page_pte_unlock(page);
        return -2;
    }

    ret = wxshadow_write_pte(page->mm, addr, entry);
    if (ret == 0)
    {
        wxshadow_invalidate_icache_all();
        spin_lock_irqsave(&wxshadow_global_lock, flags);
        if (!page->dead)
        {
            page->state = WX_STATE_SHADOW_X;
            if (page->fork_paused)
                page->fork_paused = false; /* fork 暂停的页恢复 */
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    }

    wxshadow_page_pte_unlock(page);
    return ret;
}

/* SHADOW_X -> STEPPING (r-x)：BRK 命中后切原页单步执行原始指令 */
static int wxshadow_page_begin_stepping(struct wxshadow_page *page,
                                        struct vm_area_struct *vma,
                                        unsigned long addr,
                                        struct task_struct *task)
{
    int ret;
    pteval_t entry;
    unsigned long flags;

    (void)vma;
    (void)addr;

    if (!page || !task)
        return -1;

    wxshadow_page_pte_lock(page);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page->dead || page->release_pending ||
        page->logical_release_pending ||
        page->state != WX_STATE_SHADOW_X ||
        !page->pfn_original)
    {
        bool busy = page->dead || page->release_pending ||
                    page->logical_release_pending;
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return busy ? -EBUSY : -2;
    }
    entry = wxshadow_build_stepping_original_pte(page);
    page->state = WX_STATE_STEPPING;
    page->stepping_task = task;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (!entry)
    {
        spin_lock_irqsave(&wxshadow_global_lock, flags);
        if (!page->dead && page->state == WX_STATE_STEPPING &&
            page->stepping_task == task)
        {
            page->state = WX_STATE_SHADOW_X;
            page->stepping_task = NULL;
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return -2;
    }

    ret = wxshadow_write_pte(page->mm, addr, entry);
    if (ret == 0)
    {
        wxshadow_invalidate_icache_all();
    }
    else
    {
        spin_lock_irqsave(&wxshadow_global_lock, flags);
        if (!page->dead && page->state == WX_STATE_STEPPING &&
            page->stepping_task == task)
        {
            page->state = WX_STATE_SHADOW_X;
            page->stepping_task = NULL;
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    }

    wxshadow_page_pte_unlock(page);
    return ret;
}

/* STEPPING -> SHADOW_X / 收尾释放：单步完成后切回影子页 */
static int wxshadow_page_finish_stepping(struct wxshadow_page *page,
                                         struct vm_area_struct *vma,
                                         unsigned long addr,
                                         struct task_struct *task)
{
    int ret;
    pteval_t entry;
    pteval_t original_entry;
    unsigned long flags;
    bool release_pending;
    bool logical_release_pending;
    bool was_in_list = false;

    (void)vma;
    (void)addr;

    if (!page || !task)
        return -1;

    wxshadow_page_pte_lock(page);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page->dead || page->state != WX_STATE_STEPPING ||
        page->stepping_task != task)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return -2;
    }
    release_pending = page->release_pending;
    logical_release_pending = page->logical_release_pending;
    if (!release_pending && !page->pfn_shadow)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return -2;
    }

    if (release_pending)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        original_entry = wxshadow_build_restore_original_pte(page);
        if (!original_entry)
        {
            wxshadow_page_pte_unlock(page);
            return -2;
        }

        ret = wxshadow_write_pte(page->mm, addr, original_entry);
        if (ret == 0)
            wxshadow_invalidate_icache_all();

        spin_lock_irqsave(&wxshadow_global_lock, flags);
        if (ret == 0 && page->state == WX_STATE_STEPPING &&
            page->stepping_task == task && page->release_pending)
        {
            page->dead = true;
            page->release_pending = false;
            page->logical_release_pending = false;
            page->state = WX_STATE_NONE;
            page->stepping_task = NULL;
            page->fork_paused = false;
            page->pfn_shadow = 0;
            was_in_list = !list_empty(&page->list);
            if (was_in_list)
                list_del_init(&page->list);
        }
        else if (ret == 0)
        {
            ret = -2;
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        if (ret == 0 && was_in_list)
            wxshadow_page_put(page);

        wxshadow_page_pte_unlock(page);
        return ret == 0 ? 1 : ret;
    }

    if (logical_release_pending)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        original_entry = wxshadow_build_restore_original_pte(page);
        if (!original_entry)
        {
            wxshadow_page_pte_unlock(page);
            return -2;
        }

        ret = wxshadow_write_pte(page->mm, addr, original_entry);
        if (ret == 0)
            wxshadow_invalidate_icache_all();

        spin_lock_irqsave(&wxshadow_global_lock, flags);
        if (ret == 0 && page->state == WX_STATE_STEPPING &&
            page->stepping_task == task && page->logical_release_pending &&
            !page->dead)
        {
            page->logical_release_pending = false;
            page->state = WX_STATE_DORMANT;
            page->stepping_task = NULL;
            page->fork_paused = false;
        }
        else if (ret == 0)
        {
            ret = -2;
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        wxshadow_page_pte_unlock(page);
        return ret == 0 ? 1 : ret;
    }

    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    entry = wxshadow_build_shadow_exec_pte(page);
    if (!entry)
    {
        wxshadow_page_pte_unlock(page);
        return -2;
    }

    ret = wxshadow_write_pte(page->mm, addr, entry);
    if (ret == 0)
    {
        wxshadow_invalidate_icache_all();
        spin_lock_irqsave(&wxshadow_global_lock, flags);
        if (page->state == WX_STATE_STEPPING &&
            page->stepping_task == task)
        {
            page->state = WX_STATE_SHADOW_X;
            page->stepping_task = NULL;
        }
        else
        {
            ret = -2;
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    }

    wxshadow_page_pte_unlock(page);
    return ret;
}

/* SHADOW_X -> DORMANT：hook 退休，恢复原始映射 */
static int wxshadow_page_enter_dormant_locked(struct wxshadow_page *page,
                                              struct vm_area_struct *vma,
                                              unsigned long addr)
{
    int ret;
    pteval_t entry;

    (void)vma;
    (void)addr;

    if (!page || !page->pfn_original)
        return -1;

    entry = wxshadow_build_restore_original_pte(page);
    if (!entry)
        return -1;

    ret = wxshadow_write_pte(page->mm, addr, entry);
    if (ret == 0)
    {
        unsigned long flags;

        wxshadow_invalidate_icache_all();
        spin_lock_irqsave(&wxshadow_global_lock, flags);
        if (!page->dead)
        {
            page->state = WX_STATE_DORMANT;
            page->stepping_task = NULL;
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    }

    return ret;
}

/* teardown 用：把映射恢复成原始 PTE */
static int wxshadow_page_restore_original_for_teardown_locked(struct wxshadow_page *page,
                                                              struct vm_area_struct *vma,
                                                              unsigned long addr)
{
    int ret;
    pteval_t entry;

    (void)vma;
    (void)addr;

    if (!page || !page->pfn_original)
        return -1;

    entry = wxshadow_build_restore_original_pte(page);
    if (!entry)
        return -1;

    ret = wxshadow_write_pte(page->mm, addr, entry);
    if (ret == 0)
        wxshadow_invalidate_icache_all();

    return ret;
}

/* ========== 释放 / teardown ========== */

#define WXSHADOW_RELEASE_WAIT_LOOPS 2000000

static int wxshadow_wait_for_logical_release(struct wxshadow_page *page, const char *reason)
{
    int i;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++)
    {
        bool done;
        unsigned long flags;

        spin_lock_irqsave(&wxshadow_global_lock, flags);
        done = page->dead ||
               (!page->logical_release_pending &&
                page->state == WX_STATE_DORMANT);
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        if (done)
            return 0;

        cpu_relax();
    }

    ls_log_always_tag("wxshadow", "[logical_release] 等待单步完成超时 addr=%lx (%s)\n",
                      page->page_addr, reason);
    return -EBUSY;
}

static int wxshadow_wait_for_brk_handlers(struct wxshadow_page *page, const char *reason)
{
    int i;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++)
    {
        bool done;
        unsigned long flags;

        spin_lock_irqsave(&wxshadow_global_lock, flags);
        done = page->dead || page->brk_in_flight == 0;
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        if (done)
            return 0;

        cpu_relax();
    }

    ls_log_always_tag("wxshadow", "[%s] 等待在途 BRK handler 超时 addr=%lx\n",
                      reason, page->page_addr);
    return -EBUSY;
}

static void wxshadow_clear_logical_release_pending_locked(struct wxshadow_page *page)
{
    if (page && !page->dead)
        page->logical_release_pending = false;
}

static void wxshadow_clear_logical_release_pending(struct wxshadow_page *page)
{
    unsigned long flags;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    wxshadow_clear_logical_release_pending_locked(page);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
}

/* 逻辑释放：恢复原始映射、还原影子内容，但保留影子页 */
static int wxshadow_release_page_to_clean_shadow(struct wxshadow_page *page, const char *reason)
{
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    u64 probe;
    int state;
    int ret;
    unsigned long flags;

    if (!page)
        return 0;

retry:
    wxshadow_page_pte_lock(page);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page->dead)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return 0;
    }

    if (page->release_pending)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return -EBUSY;
    }

    if (page->brk_in_flight > 0)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        ret = wxshadow_wait_for_brk_handlers(page, reason);
        if (ret < 0)
            return ret;
        goto retry;
    }

    if (page->logical_release_pending)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        cpu_relax();
        goto retry;
    }

    state = page->state;
    page->logical_release_pending = true;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (state != WX_STATE_DORMANT && state != WX_STATE_NONE)
    {
        mm = page->mm;
        if (!mm || !page->pfn_original)
        {
            ret = -EFAULT;
            goto out_fail_locked;
        }

        if (!wxshadow_is_kva((unsigned long)mm) ||
            !wxshadow_safe_read_u64((unsigned long)mm, &probe))
        {
            ret = -EFAULT;
            goto out_fail_locked;
        }

        vma = find_vma(mm, page->page_addr);
        if (!vma || vma->vm_start > page->page_addr)
        {
            ret = -EFAULT;
            goto out_fail_locked;
        }

        ret = wxshadow_page_enter_dormant_locked(page, vma, page->page_addr);
        if (ret < 0)
            goto out_fail_locked;
    }

    wxshadow_page_pte_unlock(page);

    wxshadow_sync_shadow_exec_zero(page, reason);

    ret = wxshadow_wait_for_brk_handlers(page, reason);
    if (ret < 0)
        goto out_fail_unlocked;

    wxshadow_page_pte_lock(page);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page->dead)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return 0;
    }
    if (page->release_pending || page->brk_in_flight > 0 ||
        page->state == WX_STATE_STEPPING)
    {
        wxshadow_clear_logical_release_pending_locked(page);
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        cpu_relax();
        goto retry;
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    ret = wxshadow_restore_shadow_ranges(page);
    if (ret < 0)
        goto out_fail_locked;

    wxshadow_clear_page_tracking(page);
    spin_lock_irqsave(&wxshadow_global_lock, flags);
    wxshadow_clear_logical_release_pending_locked(page);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    wxshadow_page_pte_unlock(page);

    ls_log_always_tag("wxshadow", "[release_clean] %s: addr=%lx mapping retained\n",
                      reason, page->page_addr);
    return 0;

out_fail_locked:
    spin_lock_irqsave(&wxshadow_global_lock, flags);
    wxshadow_clear_logical_release_pending_locked(page);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    wxshadow_page_pte_unlock(page);
    ls_log_always_tag("wxshadow", "[release_clean] %s 失败 addr=%lx: %d\n",
                      reason, page->page_addr, ret);
    return ret;

out_fail_unlocked:
    wxshadow_clear_logical_release_pending(page);
    ls_log_always_tag("wxshadow", "[release_clean] %s 排空 BRK handler 时失败 addr=%lx: %d\n",
                      reason, page->page_addr, ret);
    return ret;
}

static int wxshadow_release_page_logically(struct wxshadow_page *page, const char *reason)
{
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    u64 probe;
    int state;
    int ret;
    unsigned long flags;

    if (!page)
        return 0;

retry:
    wxshadow_page_pte_lock(page);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page->dead)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return 0;
    }

    if (page->brk_in_flight > 0)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        ret = wxshadow_wait_for_brk_handlers(page, reason);
        if (ret < 0)
            return ret;
        goto retry;
    }

    state = page->state;
    if (state == WX_STATE_DORMANT || state == WX_STATE_NONE)
    {
        wxshadow_clear_logical_release_pending_locked(page);
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_clear_page_tracking(page);
        wxshadow_page_pte_unlock(page);
        return 0;
    }

    page->logical_release_pending = true;
    if (state == WX_STATE_STEPPING &&
        page->stepping_task && page->stepping_task != current)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        ret = wxshadow_restore_shadow_ranges(page);
        if (ret == 0)
            wxshadow_clear_page_tracking(page);
        else
            wxshadow_clear_logical_release_pending(page);

        wxshadow_page_pte_unlock(page);
        if (ret < 0)
            return ret;

        ls_log_always_tag("wxshadow", "[logical_release] %s: addr=%lx state=%d 等待单步完成\n",
                          reason, page->page_addr, state);
        return wxshadow_wait_for_logical_release(page, reason);
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    ret = wxshadow_restore_shadow_ranges(page);
    if (ret < 0)
        goto out_fail;

    mm = page->mm;
    if (!mm || !page->pfn_original)
    {
        ret = -EFAULT;
        goto out_fail;
    }

    if (!wxshadow_is_kva((unsigned long)mm) ||
        !wxshadow_safe_read_u64((unsigned long)mm, &probe))
    {
        ret = -EFAULT;
        goto out_fail;
    }

    vma = find_vma(mm, page->page_addr);
    if (!vma || vma->vm_start > page->page_addr)
    {
        ret = -EFAULT;
        goto out_fail;
    }

    ret = wxshadow_page_enter_dormant_locked(page, vma, page->page_addr);
    if (ret < 0)
        goto out_fail;

    wxshadow_clear_page_tracking(page);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    wxshadow_clear_logical_release_pending_locked(page);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    ls_log_always_tag("wxshadow", "[logical_release] %s: addr=%lx state=%d -> DORMANT\n",
                      reason, page->page_addr, state);
    wxshadow_page_pte_unlock(page);
    return 0;

out_fail:
    wxshadow_clear_logical_release_pending(page);
    wxshadow_page_pte_unlock(page);
    ls_log_always_tag("wxshadow", "[logical_release] %s 失败 addr=%lx: %d\n",
                      reason, page->page_addr, ret);
    return ret;
}

static int wxshadow_wait_for_teardown(struct wxshadow_page *page, const char *reason)
{
    int i;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++)
    {
        bool done;
        unsigned long flags;

        spin_lock_irqsave(&wxshadow_global_lock, flags);
        done = page->dead;
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        if (done)
            return 0;

        cpu_relax();
    }

    ls_log_always_tag("wxshadow", "[teardown] 等待单步完成超时 addr=%lx (%s)\n",
                      page->page_addr, reason);
    return -EBUSY;
}

/* teardown 无法主动恢复 PTE 时，只有用户映射已消失/不再指向私有影子 PFN 才允许收尾 */
static bool wxshadow_can_finalize_failed_teardown(struct wxshadow_page *page)
{
    struct mm_struct *mm;
    pteval_t pte_val;
    unsigned long current_pfn;

    if (!page)
        return false;

    if (!page->pfn_shadow)
        return true;

    mm = page->mm;
    if (!mm || !wxshadow_is_kva((unsigned long)mm))
        return false;

    if (wxshadow_read_pte(mm, page->page_addr, &pte_val) < 0)
        return true;

    if (!(pte_val & PTE_VALID))
        return true;

    current_pfn = (pte_val & WXSHADOW_PTE_PFN_MASK) >> PAGE_SHIFT;
    if (page->pfn_shadow && current_pfn == page->pfn_shadow)
    {
        ls_log_always_tag("wxshadow", "[teardown] addr=%lx 恢复失败后仍映射到私有 pfn=%lx\n",
                          page->page_addr, current_pfn);
        return false;
    }

    return true;
}

/*
 * wxshadow_teardown_page - 统一页面清理。
 * 1. global_lock 下：标记 dead、清 stepping_task、pfn_shadow 置零、从 list 摘除。
 * 2. 对 stepping 任务禁用单步（带指针校验）。
 * 3. 短暂自旋覆盖并发 step handler 的 STEPPING 竞态窗口。
 * 4. 恢复 PTE 到原始页（mm/VMA 仍有效时）。
 * 5. 释放 list 引用。
 * 影子页内存在 wxshadow_page_put 最后一个引用释放时回收。
 * 调用者必须持有引用（find_page 得到），用完后调 wxshadow_page_put。
 */
static int wxshadow_teardown_page(struct wxshadow_page *page, const char *reason)
{
    struct task_struct *stepping = NULL;
    int state;
    bool was_in_list;
    bool finalize_teardown = true;
    int ret = 0;
    unsigned long flags;

    if (!page)
        return 0;

    wxshadow_page_pte_lock(page);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page->dead)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        return 0;
    }

    state = page->state;
    page->release_pending = true;
    if (state == WX_STATE_STEPPING &&
        page->stepping_task && page->stepping_task != current)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page);
        ls_log_always_tag("wxshadow", "[teardown] %s: addr=%lx state=%d 等待单步完成\n",
                          reason, page->page_addr, state);
        return wxshadow_wait_for_teardown(page, reason);
    }

    stepping = page->stepping_task;
    was_in_list = !list_empty(&page->list);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    ls_log_always_tag("wxshadow", "[teardown] %s: addr=%lx state=%d\n",
                      reason, page->page_addr, state);

    /* 禁用单步（带校验） */
    if (stepping && stepping != current && wxshadow_fn_user_disable_single_step)
    {
        u64 probe;
        if (wxshadow_is_kva((unsigned long)stepping) &&
            wxshadow_safe_read_u64((unsigned long)stepping, &probe))
            KCALL_1(wxshadow_fn_user_disable_single_step, void, stepping);
        else
            ls_log_always_tag("wxshadow", "[teardown] stepping_task %px 已失效，跳过禁用\n", stepping);
    }

    /* STEPPING 竞态：短暂自旋 */
    if (state == WX_STATE_STEPPING && stepping && stepping != current)
    {
        int w;
        for (w = 0; w < 50000; w++)
            cpu_relax();
    }

    /* 恢复 PTE */
    if (page->mm && page->pfn_original)
    {
        struct mm_struct *mm = page->mm;
        u64 probe;

        if (!wxshadow_is_kva((unsigned long)mm) ||
            !wxshadow_safe_read_u64((unsigned long)mm, &probe))
        {
            ls_log_always_tag("wxshadow", "[teardown] mm %px 无效 addr=%lx\n",
                              mm, page->page_addr);
            ret = -EFAULT;
        }
        else
        {
            struct vm_area_struct *vma = find_vma(mm, page->page_addr);
            if (!vma || vma->vm_start > page->page_addr)
            {
                ls_log_always_tag("wxshadow", "[teardown] %s 期间 addr=%lx 无 vma\n",
                                  reason, page->page_addr);
                ret = -EFAULT;
            }
            else
            {
                ret = wxshadow_page_restore_original_for_teardown_locked(page, vma, page->page_addr);
                if (ret != 0)
                    ls_log_always_tag("wxshadow", "[teardown] 恢复映射失败 addr=%lx: %d\n",
                                      page->page_addr, ret);
            }
        }
    }
    else if (page->pfn_original)
    {
        ls_log_always_tag("wxshadow", "[teardown] %s 期间 addr=%lx 缺 mm 元数据\n",
                          reason, page->page_addr);
        ret = -EFAULT;
    }

    if (ret < 0)
    {
        finalize_teardown = wxshadow_can_finalize_failed_teardown(page);
        if (!finalize_teardown)
        {
            spin_lock_irqsave(&wxshadow_global_lock, flags);
            if (!page->dead)
                page->release_pending = false;
            spin_unlock_irqrestore(&wxshadow_global_lock, flags);
            wxshadow_page_pte_unlock(page);
            ls_log_always_tag("wxshadow", "[teardown] 恢复失败后保留页面 addr=%lx (%d)\n",
                              page->page_addr, ret);
            return ret;
        }

        ls_log_always_tag("wxshadow", "[teardown] 不恢复直接收尾 addr=%lx；映射已脱离\n",
                          page->page_addr);
        ret = 0;
    }
    else
    {
        wxshadow_sync_shadow_exec_zero(page, reason);
    }

    /* 标记 dead、摘 list（映射恢复之后） */
    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (!page->dead)
    {
        page->dead = true;
        page->release_pending = false;
        page->logical_release_pending = false;
        page->state = WX_STATE_NONE;
        page->stepping_task = NULL;
        page->fork_paused = false;

        /* 影子页内存在 wxshadow_page_put 时释放，防止并发引用者 UAF */
        page->pfn_shadow = 0;

        if (was_in_list && !list_empty(&page->list))
            list_del_init(&page->list);
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (was_in_list)
        wxshadow_page_put(page);

    wxshadow_page_pte_unlock(page);
    return ret;
}

static int wxshadow_teardown_pages_for_mm_impl(struct mm_struct *mm, const char *reason,
                                               bool strict)
{
    struct list_head *pos;
    struct wxshadow_page *page;
    int count = 0;
    int first_err = 0;
    unsigned long flags;

    while (1)
    {
        page = NULL;
        spin_lock_irqsave(&wxshadow_global_lock, flags);
        list_for_each(pos, &wxshadow_page_list)
        {
            struct wxshadow_page *p = container_of(pos, struct wxshadow_page, list);
            if (!mm || p->mm == mm)
            {
                p->refcount++;
                page = p;
                break;
            }
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        if (!page)
            break;

        {
            int ret = wxshadow_teardown_page(page, reason);
            if (ret < 0 && first_err == 0)
                first_err = ret;
            if (ret < 0)
            {
                wxshadow_page_put(page);
                break;
            }
        }
        wxshadow_page_put(page);
        count++;
    }

    if (count > 0)
        ls_log_always_tag("wxshadow", "[%s] 清理 %d 个页面\n", reason, count);
    if (first_err < 0)
        ls_log_always_tag("wxshadow", "[%s] 清理遇到恢复失败，first=%d\n", reason, first_err);

    return strict ? first_err : count;
}

static int wxshadow_teardown_pages_for_mm(struct mm_struct *mm, const char *reason)
{
    return wxshadow_teardown_pages_for_mm_impl(mm, reason, false);
}

static int wxshadow_release_pages_for_mm(struct mm_struct *mm, const char *reason)
{
    struct wxshadow_page *batch[32];
    struct list_head *pos;
    int nr;
    int i;
    int count = 0;
    int first_err = 0;
    bool stop = false;
    unsigned long flags;

    do
    {
        nr = 0;

        spin_lock_irqsave(&wxshadow_global_lock, flags);
        list_for_each(pos, &wxshadow_page_list)
        {
            struct wxshadow_page *p = container_of(pos, struct wxshadow_page, list);

            if (p->dead || p->state == WX_STATE_NONE ||
                p->state == WX_STATE_DORMANT || !p->pfn_shadow)
                continue;
            if (mm && p->mm != mm)
                continue;

            p->refcount++;
            batch[nr++] = p;
            if (nr >= (int)(sizeof(batch) / sizeof(batch[0])))
                break;
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        if (nr == 0)
            break;

        for (i = 0; i < nr; i++)
        {
            int ret = wxshadow_release_page_to_clean_shadow(batch[i], reason);

            if (ret < 0 && first_err == 0)
                first_err = ret;
            if (ret < 0)
            {
                bool still_active;

                spin_lock_irqsave(&wxshadow_global_lock, flags);
                still_active = !batch[i]->dead &&
                               batch[i]->state != WX_STATE_DORMANT;
                spin_unlock_irqrestore(&wxshadow_global_lock, flags);
                if (still_active)
                    stop = true;
            }

            wxshadow_page_put(batch[i]);
            count++;
        }
    } while (!stop && nr == (int)(sizeof(batch) / sizeof(batch[0])));

    if (count > 0)
        ls_log_always_tag("wxshadow", "[%s] 逻辑释放 %d 个页面\n", reason, count);
    if (first_err < 0)
        ls_log_always_tag("wxshadow", "[%s] 逻辑释放失败，first=%d\n", reason, first_err);

    return first_err;
}

/* 写故障：页面内容即将被进程修改，逻辑释放 hook 防止脏影子页残留 */
static int wxshadow_handle_write_fault(struct mm_struct *mm, unsigned long addr)
{
    struct wxshadow_page *page;
    int ret;
    unsigned long flags;

    page = wxshadow_find_page(mm, addr);
    if (!page)
        return -1;

    if (page->state == WX_STATE_NONE)
    {
        wxshadow_page_put(page);
        return -1;
    }

    ls_log_always_tag("wxshadow", "write fault at %lx - page content changing\n", addr);

    ret = wxshadow_release_page_logically(page, "Write Fault (page modified)");
    if (ret == 0)
    {
        /*
         * 故障会继续走内核正常写路径，COW/写保护解析后原 PFN 可能失效，
         * 下次复用时重新快照。
         */
        spin_lock_irqsave(&wxshadow_global_lock, flags);
        if (!page->dead && page->state == WX_STATE_DORMANT)
        {
            page->pfn_original = 0;
            page->pte_original = 0;
            page->fork_paused = false;
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    }
    wxshadow_page_put(page);

    return -1;
}

/* ========== 影子页写入上下文（set_bp / patch 共用） ========== */

struct wxshadow_write_ctx
{
    const char *op;
    struct vm_area_struct *vma;
    struct wxshadow_page *page_info;
    void *orig_kaddr;
    unsigned long page_addr;
    bool is_new;
    bool needs_activation;
};

static int wxshadow_prepare_shadow_target(struct mm_struct *mm, unsigned long addr,
                                          unsigned long page_addr, const char *op,
                                          struct vm_area_struct **out_vma)
{
    struct vm_area_struct *vma;
    int ret;

    vma = find_vma(mm, addr);
    if (!vma || vma->vm_start > addr)
    {
        ls_log_always_tag("wxshadow", "[%s] addr %lx 无 vma\n", op, addr);
        return -1;
    }

    ret = wxshadow_try_split_pmd(mm, vma, page_addr);
    if (ret < 0)
    {
        ls_log_always_tag("wxshadow", "[%s] PMD 拆分失败 %lx: %d\n", op, page_addr, ret);
        return ret;
    }

    *out_vma = vma;
    return 0;
}

static struct wxshadow_page *wxshadow_find_usable_shadow_page(struct mm_struct *mm,
                                                              unsigned long page_addr)
{
    struct wxshadow_page *page_info;
    bool usable;
    unsigned long flags;

    page_info = wxshadow_find_page(mm, page_addr);
    if (!page_info)
        return NULL;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    usable = !page_info->dead && page_info->shadow_page != NULL;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (usable)
        return page_info;

    wxshadow_page_put(page_info);
    return NULL;
}

static int wxshadow_create_shadow_page_common(struct mm_struct *mm, unsigned long page_addr,
                                              const char *op,
                                              struct wxshadow_page **out_page_info,
                                              void **out_orig_kaddr)
{
    struct wxshadow_page *page_info;
    pteval_t pte;
    unsigned long orig_pfn;
    unsigned long shadow_vaddr;

    page_info = wxshadow_create_page(mm, page_addr);
    if (!page_info)
    {
        ls_log_always_tag("wxshadow", "[%s] 创建页面结构失败\n", op);
        return -ENOMEM;
    }

    if (wxshadow_read_pte(mm, page_addr, &pte) < 0 || !(pte & PTE_VALID))
    {
        ls_log_always_tag("wxshadow", "[%s] addr %lx 无 pte\n", op, page_addr);
        goto err_fault;
    }

    orig_pfn = (pte & WXSHADOW_PTE_PFN_MASK) >> PAGE_SHIFT;
    page_info->pfn_original = orig_pfn;
    page_info->pte_original = pte;
    *out_orig_kaddr = wxshadow_pfn_to_kaddr(orig_pfn);
    if (!wxshadow_is_kva((unsigned long)*out_orig_kaddr))
    {
        ls_log_always_tag("wxshadow", "[%s] orig_kaddr %px 无效 pfn=%lx\n",
                          op, *out_orig_kaddr, orig_pfn);
        goto err_fault;
    }

    shadow_vaddr = __get_free_pages(GFP_KERNEL, 0);
    if (!shadow_vaddr)
    {
        ls_log_always_tag("wxshadow", "[%s] 分配影子页失败\n", op);
        goto err_nomem;
    }

    page_info->pfn_shadow = virt_to_phys((void *)shadow_vaddr) >> PAGE_SHIFT;
    page_info->shadow_page = (void *)shadow_vaddr;

    *out_page_info = page_info;
    return 0;

err_fault:
    wxshadow_free_page(page_info);
    wxshadow_page_put(page_info);
    return -EFAULT;

err_nomem:
    wxshadow_free_page(page_info);
    wxshadow_page_put(page_info);
    return -ENOMEM;
}

static int wxshadow_prepare_existing_shadow_page(struct wxshadow_page *page_info,
                                                 unsigned long page_addr,
                                                 const char *op,
                                                 bool *out_needs_activation,
                                                 bool *out_needs_refresh)
{
    int i;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++)
    {
        bool busy;
        bool dead;
        bool needs_activation;
        bool needs_refresh;
        unsigned long flags;

        spin_lock_irqsave(&wxshadow_global_lock, flags);
        dead = page_info->dead;
        busy = page_info->release_pending ||
               page_info->logical_release_pending ||
               page_info->brk_in_flight > 0 ||
               page_info->state == WX_STATE_STEPPING;
        needs_activation = !dead && page_info->state != WX_STATE_SHADOW_X;
        needs_refresh = !dead && page_info->state == WX_STATE_DORMANT;
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        if (dead)
            return 1;

        if (!busy)
        {
            if (out_needs_activation)
                *out_needs_activation = needs_activation;
            if (out_needs_refresh)
                *out_needs_refresh = needs_refresh;
            return 0;
        }

        cpu_relax();
    }

    ls_log_always_tag("wxshadow", "[%s] page %lx 单步/释放在途\n", op, page_addr);
    return -EBUSY;
}

/* DORMANT 页复用时，从当前 PTE 重新快照并刷新影子内容 */
static int wxshadow_refresh_dormant_shadow_page(struct wxshadow_page *page_info,
                                                struct mm_struct *mm,
                                                unsigned long page_addr,
                                                const char *op)
{
    pteval_t pte;
    unsigned long orig_pfn;
    unsigned long shadow_vaddr;
    void *orig_kaddr;
    unsigned long flags;

    if (!page_info || !mm)
        return -EINVAL;

    wxshadow_page_pte_lock(page_info);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page_info->dead || page_info->release_pending ||
        page_info->logical_release_pending ||
        page_info->state != WX_STATE_DORMANT ||
        !page_info->shadow_page)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page_info);
        return 0;
    }
    shadow_vaddr = (unsigned long)page_info->shadow_page;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (wxshadow_read_pte(mm, page_addr, &pte) < 0 || !(pte & PTE_VALID))
    {
        ls_log_always_tag("wxshadow", "[%s] 刷新 DORMANT 页 %lx 时无 pte\n", op, page_addr);
        wxshadow_page_pte_unlock(page_info);
        return -EFAULT;
    }

    orig_pfn = (pte & WXSHADOW_PTE_PFN_MASK) >> PAGE_SHIFT;
    orig_kaddr = wxshadow_pfn_to_kaddr(orig_pfn);
    if (!wxshadow_is_kva((unsigned long)orig_kaddr))
    {
        ls_log_always_tag("wxshadow", "[%s] DORMANT 页 %lx pfn %lx 的 orig_kaddr %px 无效\n",
                          op, page_addr, orig_pfn, orig_kaddr);
        wxshadow_page_pte_unlock(page_info);
        return -EFAULT;
    }

    memcpy((void *)shadow_vaddr, orig_kaddr, PAGE_SIZE);
    wxshadow_sync_shadow_code(shadow_vaddr, PAGE_SIZE);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (!page_info->dead && page_info->state == WX_STATE_DORMANT)
    {
        page_info->pfn_original = orig_pfn;
        page_info->pte_original = pte;
        page_info->fork_paused = false;
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    wxshadow_page_pte_unlock(page_info);

    ls_log_always_tag("wxshadow", "[%s] 刷新 DORMANT 页 %lx -> pfn %lx\n",
                      op, page_addr, orig_pfn);
    return 0;
}

static int wxshadow_acquire_shadow_page_for_write(struct mm_struct *mm, unsigned long addr,
                                                  unsigned long page_addr, const char *op,
                                                  struct vm_area_struct **out_vma,
                                                  struct wxshadow_page **out_page_info,
                                                  void **out_orig_kaddr,
                                                  bool *out_is_new,
                                                  bool *out_needs_activation)
{
    struct wxshadow_page *page_info;
    bool needs_refresh = false;
    int ret;

    *out_page_info = NULL;
    *out_orig_kaddr = NULL;
    *out_is_new = false;
    if (out_needs_activation)
        *out_needs_activation = false;

    ret = wxshadow_prepare_shadow_target(mm, addr, page_addr, op, out_vma);
    if (ret < 0)
        return ret;

    for (;;)
    {
        page_info = wxshadow_find_usable_shadow_page(mm, page_addr);
        if (!page_info)
            break;

        ret = wxshadow_prepare_existing_shadow_page(page_info, page_addr, op,
                                                    out_needs_activation,
                                                    &needs_refresh);
        if (ret > 0)
        {
            wxshadow_page_put(page_info);
            continue;
        }
        if (ret < 0)
        {
            wxshadow_page_put(page_info);
            return ret;
        }

        if (needs_refresh)
        {
            ret = wxshadow_refresh_dormant_shadow_page(page_info, mm, page_addr, op);
            if (ret < 0)
            {
                wxshadow_page_put(page_info);
                return ret;
            }
        }

        *out_page_info = page_info;
        return 0;
    }

    ret = wxshadow_create_shadow_page_common(mm, page_addr, op, out_page_info, out_orig_kaddr);
    if (ret < 0)
        return ret;

    *out_is_new = true;
    if (out_needs_activation)
        *out_needs_activation = true;
    return 0;
}

static void wxshadow_destroy_unactivated_shadow_page(struct wxshadow_page *page_info)
{
    if (!page_info)
        return;

    wxshadow_free_page(page_info);
    wxshadow_page_put(page_info);
}

static int wxshadow_acquire_write_ctx(struct mm_struct *mm, unsigned long addr,
                                      const char *op, struct wxshadow_write_ctx *ctx)
{
    int ret;

    if (!ctx)
        return -EINVAL;

    memset(ctx, 0, sizeof(*ctx));
    ctx->op = op;
    ctx->page_addr = addr & PAGE_MASK;

    return wxshadow_acquire_shadow_page_for_write(mm, addr, ctx->page_addr, op,
                                                  &ctx->vma, &ctx->page_info,
                                                  &ctx->orig_kaddr, &ctx->is_new,
                                                  &ctx->needs_activation);
}

static void wxshadow_put_write_ctx(struct wxshadow_write_ctx *ctx)
{
    if (!ctx || !ctx->page_info)
        return;

    wxshadow_page_put(ctx->page_info);
    ctx->page_info = NULL;
}

static void wxshadow_abort_write_ctx(struct wxshadow_write_ctx *ctx)
{
    if (!ctx || !ctx->page_info)
        return;

    if (ctx->is_new)
        wxshadow_destroy_unactivated_shadow_page(ctx->page_info);
    else
        wxshadow_page_put(ctx->page_info);
    ctx->page_info = NULL;
}

static int wxshadow_activate_write_ctx(struct wxshadow_write_ctx *ctx, bool force_activation)
{
    if (!ctx || !ctx->page_info)
        return -EINVAL;

    if (!force_activation && !ctx->needs_activation)
        return 0;

    return wxshadow_page_activate_shadow(ctx->page_info, ctx->vma, ctx->page_addr);
}

static u64 wxshadow_next_mod_serial_locked(struct wxshadow_page *page_info)
{
    page_info->next_mod_serial++;
    if (page_info->next_mod_serial == 0)
        page_info->next_mod_serial++;
    return page_info->next_mod_serial;
}

static int wxshadow_ensure_bp_slot(struct wxshadow_page *page_info, unsigned long addr)
{
    int i;
    int free_idx = -1;
    unsigned long flags;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    for (i = 0; i < page_info->nr_bps; i++)
    {
        if (page_info->bps[i].addr == addr)
        {
            if (!page_info->bps[i].active)
            {
                memset(&page_info->bps[i], 0, sizeof(page_info->bps[i]));
                page_info->bps[i].addr = addr;
            }
            page_info->bps[i].active = true;
            page_info->bps[i].serial = wxshadow_next_mod_serial_locked(page_info);
            spin_unlock_irqrestore(&wxshadow_global_lock, flags);
            return i;
        }
        if (free_idx < 0 && !page_info->bps[i].active)
            free_idx = i;
    }

    if (free_idx < 0)
    {
        if (page_info->nr_bps >= WXSHADOW_MAX_BPS_PER_PAGE)
        {
            spin_unlock_irqrestore(&wxshadow_global_lock, flags);
            return -ENOSPC;
        }
        free_idx = page_info->nr_bps++;
    }

    memset(&page_info->bps[free_idx], 0, sizeof(page_info->bps[free_idx]));
    page_info->bps[free_idx].addr = addr;
    page_info->bps[free_idx].active = true;
    page_info->bps[free_idx].serial = wxshadow_next_mod_serial_locked(page_info);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    return free_idx;
}

static int wxshadow_copy_original_page_to_shadow(struct wxshadow_page *page_info,
                                                 const void *orig_kaddr)
{
    if (!page_info || !page_info->shadow_page || !orig_kaddr)
        return -EINVAL;

    memcpy(page_info->shadow_page, orig_kaddr, PAGE_SIZE);
    return 0;
}

static int wxshadow_prepare_new_write_ctx(struct wxshadow_write_ctx *ctx)
{
    if (!ctx || !ctx->page_info || !ctx->is_new)
        return -EINVAL;

    return wxshadow_copy_original_page_to_shadow(ctx->page_info, ctx->orig_kaddr);
}

static int wxshadow_write_shadow_bytes(struct wxshadow_page *page_info,
                                       unsigned long offset,
                                       const void *src, unsigned long len)
{
    unsigned long shadow_vaddr;

    if (!page_info || !page_info->shadow_page || !src || len == 0 ||
        offset + len > PAGE_SIZE)
        return -EINVAL;

    shadow_vaddr = (unsigned long)page_info->shadow_page;
    memcpy((void *)(shadow_vaddr + offset), src, len);
    wxshadow_sync_shadow_code(shadow_vaddr, PAGE_SIZE);
    return 0;
}

static int wxshadow_write_shadow_u32(struct wxshadow_page *page_info, unsigned long offset, u32 value)
{
    return wxshadow_write_shadow_bytes(page_info, offset, &value, sizeof(value));
}

static int wxshadow_upsert_patch_record(struct wxshadow_page *page_info,
                                        unsigned long offset, unsigned long len,
                                        void *patch_data, void **out_old_data,
                                        unsigned long *out_rebuild_len)
{
    int i;
    int free_idx = -1;
    int idx = -1;
    unsigned long rebuild_len = len;
    void *old_data = NULL;
    unsigned long flags;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    for (i = 0; i < page_info->nr_patches; i++)
    {
        if (page_info->patches[i].active &&
            page_info->patches[i].offset == offset)
        {
            idx = i;
            old_data = page_info->patches[i].data;
            if (page_info->patches[i].len > rebuild_len)
                rebuild_len = page_info->patches[i].len;
            break;
        }
        if (free_idx < 0 && !page_info->patches[i].active &&
            !page_info->patches[i].data)
            free_idx = i;
    }

    if (idx < 0)
    {
        if (free_idx < 0)
        {
            if (page_info->nr_patches >= WXSHADOW_MAX_PATCHES_PER_PAGE)
            {
                spin_unlock_irqrestore(&wxshadow_global_lock, flags);
                return -ENOSPC;
            }
            free_idx = page_info->nr_patches++;
        }
        idx = free_idx;
        memset(&page_info->patches[idx], 0, sizeof(page_info->patches[idx]));
    }

    page_info->patches[idx].offset = (u16)offset;
    page_info->patches[idx].len = (u16)len;
    page_info->patches[idx].active = true;
    page_info->patches[idx].data = patch_data;
    page_info->patches[idx].serial = wxshadow_next_mod_serial_locked(page_info);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (out_old_data)
        *out_old_data = old_data;
    if (out_rebuild_len)
        *out_rebuild_len = rebuild_len;

    wxshadow_sync_page_tracking(page_info);
    return 0;
}

struct wxshadow_shadow_apply_op
{
    u64 serial;
    unsigned long offset;
    unsigned long len;
    const void *data;
    bool is_bp;
};

/*
 * 重建影子页 [offset, offset+len) 区间：
 * 先复制原始内容，再按 serial 顺序叠加 patch 和 BRK 断点。
 */
static int wxshadow_rebuild_shadow_range(struct wxshadow_page *page_info,
                                         unsigned long offset, unsigned long len)
{
    struct wxshadow_shadow_apply_op *ops = NULL;
    int nr_ops_max;
    unsigned long original_pfn;
    unsigned long shadow_vaddr;
    unsigned long range_end;
    const char *original_kaddr;
    int nr_ops = 0;
    int i;
    int j;
    unsigned long flags;

    if (!page_info)
        return -EINVAL;
    if (len == 0)
        return 0;
    if (offset >= PAGE_SIZE || offset + len > PAGE_SIZE)
        return -EINVAL;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (!page_info->shadow_page || !page_info->pfn_original)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        return -EFAULT;
    }
    nr_ops_max = page_info->nr_patches + page_info->nr_bps;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (nr_ops_max > 0)
    {
        ops = kcalloc(nr_ops_max, sizeof(*ops), GFP_KERNEL);
        if (!ops)
            return -ENOMEM;
    }

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (!page_info->shadow_page || !page_info->pfn_original)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        kfree(ops);
        return -EFAULT;
    }

    original_pfn = page_info->pfn_original;
    shadow_vaddr = (unsigned long)page_info->shadow_page;
    range_end = offset + len;

    for (i = 0; i < page_info->nr_patches && nr_ops < nr_ops_max; i++)
    {
        struct wxshadow_patch *patch = &page_info->patches[i];
        unsigned long patch_end;

        if (!patch->active || !patch->data || patch->len == 0)
            continue;

        patch_end = patch->offset + patch->len;
        if (patch->offset >= range_end || patch_end <= offset)
            continue;

        ops[nr_ops].serial = patch->serial;
        ops[nr_ops].offset = patch->offset;
        ops[nr_ops].len = patch->len;
        ops[nr_ops].data = patch->data;
        ops[nr_ops].is_bp = false;
        nr_ops++;
    }

    for (i = 0; i < page_info->nr_bps && nr_ops < nr_ops_max; i++)
    {
        struct wxshadow_bp *bp = &page_info->bps[i];
        unsigned long bp_offset;
        unsigned long bp_end;

        if (!bp->active)
            continue;

        bp_offset = bp->addr & ~PAGE_MASK;
        bp_end = bp_offset + AARCH64_INSN_SIZE;
        if (bp_offset >= range_end || bp_end <= offset)
            continue;

        ops[nr_ops].serial = bp->serial;
        ops[nr_ops].offset = bp_offset;
        ops[nr_ops].len = AARCH64_INSN_SIZE;
        ops[nr_ops].data = NULL;
        ops[nr_ops].is_bp = true;
        nr_ops++;
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    original_kaddr = (const char *)wxshadow_pfn_to_kaddr(original_pfn);
    if (!wxshadow_is_kva((unsigned long)original_kaddr))
    {
        kfree(ops);
        return -EFAULT;
    }

    memcpy((void *)(shadow_vaddr + offset), original_kaddr + offset, len);

    /* 插入排序（按 serial） */
    for (i = 1; i < nr_ops; i++)
    {
        struct wxshadow_shadow_apply_op op = ops[i];

        for (j = i - 1; j >= 0 && ops[j].serial > op.serial; j--)
            ops[j + 1] = ops[j];
        ops[j + 1] = op;
    }

    for (i = 0; i < nr_ops; i++)
    {
        unsigned long apply_start = ops[i].offset;
        unsigned long apply_end = ops[i].offset + ops[i].len;
        const char *src;
        u32 brk_insn = WXSHADOW_BRK_INSN;

        if (apply_start < offset)
            apply_start = offset;
        if (apply_end > range_end)
            apply_end = range_end;
        if (apply_start >= apply_end)
            continue;

        if (ops[i].is_bp)
            src = (const char *)&brk_insn;
        else
            src = (const char *)ops[i].data;

        memcpy((void *)(shadow_vaddr + apply_start),
               src + (apply_start - ops[i].offset),
               apply_end - apply_start);
    }

    wxshadow_sync_shadow_code(shadow_vaddr, PAGE_SIZE);
    kfree(ops);
    return 0;
}

static bool wxshadow_page_has_active_mods_locked(struct wxshadow_page *page_info)
{
    int i;

    for (i = 0; i < page_info->nr_bps; i++)
    {
        if (page_info->bps[i].active)
            return true;
    }
    for (i = 0; i < page_info->nr_patches; i++)
    {
        if (page_info->patches[i].active)
            return true;
    }
    return false;
}

#define WXSHADOW_RELEASE_MATCH_BP (1U << 0)
#define WXSHADOW_RELEASE_MATCH_PATCH (1U << 1)

static int wxshadow_wait_for_release_brk_handlers(struct wxshadow_page *page_info,
                                                  const char *reason)
{
    int i;

    if (!page_info)
        return -EINVAL;

    for (i = 0; i < WXSHADOW_RELEASE_WAIT_LOOPS; i++)
    {
        bool done;
        unsigned long flags;

        spin_lock_irqsave(&wxshadow_global_lock, flags);
        done = page_info->dead || page_info->brk_in_flight == 0;
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        if (done)
            return 0;

        cpu_relax();
    }

    ls_log_always_tag("wxshadow", "[%s] 等待在途 BRK handler 超时 addr=%lx\n",
                      reason, page_info->page_addr);
    return -EBUSY;
}

/*
 * 释放指定地址的断点/patch：重建影子区间；若页面已无活跃修改则整页 teardown。
 */
static int wxshadow_release_mod_at_addr(struct wxshadow_page *page_info,
                                        unsigned long addr,
                                        unsigned int match_flags,
                                        const char *reason)
{
    void *free_patch_data[WXSHADOW_MAX_PATCHES_PER_PAGE];
    unsigned long offset = addr & ~PAGE_MASK;
    unsigned long range_start = PAGE_SIZE;
    unsigned long range_end = 0;
    bool wait_brk_handlers = false;
    bool matched = false;
    bool has_remaining;
    int nr_free = 0;
    int ret = 0;
    int i;
    unsigned long flags;

    if (!page_info)
        return -EINVAL;

retry:
    wxshadow_page_pte_lock(page_info);

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page_info->dead || !page_info->shadow_page)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page_info);
        return -ENODATA;
    }
    wait_brk_handlers = page_info->brk_in_flight > 0;
    if (page_info->release_pending || page_info->state == WX_STATE_STEPPING ||
        wait_brk_handlers || page_info->logical_release_pending)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page_info);
        if (wait_brk_handlers)
        {
            ret = wxshadow_wait_for_release_brk_handlers(page_info, reason);
            if (ret < 0)
                return ret;
        }
        else
        {
            cpu_relax();
        }
        goto retry;
    }
    page_info->logical_release_pending = true;
    if (page_info->dead || !page_info->shadow_page)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page_info);
        return -ENODATA;
    }
    if (page_info->release_pending || page_info->state == WX_STATE_STEPPING ||
        page_info->brk_in_flight > 0)
    {
        wxshadow_clear_logical_release_pending_locked(page_info);
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_pte_unlock(page_info);
        cpu_relax();
        goto retry;
    }

    if (match_flags & WXSHADOW_RELEASE_MATCH_BP)
    {
        for (i = 0; i < page_info->nr_bps; i++)
        {
            struct wxshadow_bp *bp = &page_info->bps[i];

            if (!bp->active || bp->addr != addr)
                continue;

            bp->active = false;
            bp->serial = 0;
            memset(bp->reg_mods, 0, sizeof(bp->reg_mods));
            bp->nr_reg_mods = 0;
            if (range_start > offset)
                range_start = offset;
            if (range_end < offset + AARCH64_INSN_SIZE)
                range_end = offset + AARCH64_INSN_SIZE;
            matched = true;
        }
    }

    if (match_flags & WXSHADOW_RELEASE_MATCH_PATCH)
    {
        for (i = 0; i < page_info->nr_patches; i++)
        {
            struct wxshadow_patch *patch = &page_info->patches[i];

            if (!patch->active || patch->offset != offset)
                continue;

            if (patch->data)
                free_patch_data[nr_free++] = patch->data;
            if (range_start > patch->offset)
                range_start = patch->offset;
            if (range_end < patch->offset + patch->len)
                range_end = patch->offset + patch->len;
            patch->active = false;
            patch->serial = 0;
            patch->len = 0;
            patch->data = NULL;
            matched = true;
        }
    }

    has_remaining = wxshadow_page_has_active_mods_locked(page_info);
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (!matched)
    {
        ls_log_always_tag("wxshadow", "[release] addr=%lx (page=%lx offset=%lx) 无匹配修改\n",
                          addr, page_info->page_addr, offset);
        wxshadow_clear_logical_release_pending(page_info);
        wxshadow_page_pte_unlock(page_info);
        return -ENODATA;
    }

    wxshadow_sync_page_tracking(page_info);

    if (range_start < range_end)
        ret = wxshadow_rebuild_shadow_range(page_info, range_start, range_end - range_start);
    wxshadow_clear_logical_release_pending(page_info);

    wxshadow_page_pte_unlock(page_info);

    for (i = 0; i < nr_free; i++)
        kfree(free_patch_data[i]);

    if (ret < 0)
    {
        /* 重建失败：直接整页退休，避免残留脏影子映射 */
        (void)wxshadow_teardown_page(page_info, reason);
        return ret;
    }

    if (!has_remaining)
    {
        ret = wxshadow_teardown_page(page_info, reason);
        if (ret < 0)
            return ret;
    }

    return 0;
}

/* ========== 断点操作 ========== */

static int wxshadow_do_set_bp(struct mm_struct *mm, unsigned long addr)
{
    struct wxshadow_write_ctx ctx;
    unsigned long offset = addr & ~PAGE_MASK;
    int ret;
    int bp_idx;

    ls_log_always_tag("wxshadow", "[set_bp] addr=%lx\n", addr);

    ret = wxshadow_acquire_write_ctx(mm, addr, "set_bp", &ctx);
    if (ret < 0)
        return ret;

    bp_idx = wxshadow_ensure_bp_slot(ctx.page_info, addr);
    if (bp_idx < 0)
    {
        ls_log_always_tag("wxshadow", "[set_bp] page %lx 断点过多\n", ctx.page_addr);
        wxshadow_abort_write_ctx(&ctx);
        return bp_idx;
    }

    if (!ctx.is_new)
    {
        ret = wxshadow_write_shadow_u32(ctx.page_info, offset, WXSHADOW_BRK_INSN);
        if (ret < 0)
            goto out_abort;
        wxshadow_mark_bp_dirty(ctx.page_info, offset);
        ret = wxshadow_activate_write_ctx(&ctx, false);
        if (ret < 0)
            goto out_abort;
        ls_log_always_tag("wxshadow", "bp at %lx (existing page)\n", addr);
        wxshadow_put_write_ctx(&ctx);
        return 0;
    }

    ret = wxshadow_prepare_new_write_ctx(&ctx);
    if (ret < 0)
        goto out_abort;
    ret = wxshadow_write_shadow_u32(ctx.page_info, offset, WXSHADOW_BRK_INSN);
    if (ret < 0)
        goto out_abort;
    wxshadow_mark_bp_dirty(ctx.page_info, offset);

    ret = wxshadow_activate_write_ctx(&ctx, true);
    if (ret == 0)
    {
        ls_log_always_tag("wxshadow", "bp at %lx orig_pfn=%lx shadow_pfn=%lx\n",
                          addr, ctx.page_info->pfn_original, ctx.page_info->pfn_shadow);
        wxshadow_put_write_ctx(&ctx);
    }
    else
    {
        ls_log_always_tag("wxshadow", "[set_bp] 切换映射失败\n");
        goto out_abort;
    }

    return ret;

out_abort:
    wxshadow_abort_write_ctx(&ctx);
    return ret;
}

static int wxshadow_do_set_reg(struct mm_struct *mm, unsigned long addr,
                               unsigned int reg_idx, unsigned long value)
{
    struct wxshadow_page *page_info;
    struct wxshadow_bp *bp;
    int i;

    if (reg_idx > 31)
        return -EINVAL;

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info)
        return -ENOENT;

    bp = wxshadow_find_bp(page_info, addr);
    if (!bp)
    {
        wxshadow_page_put(page_info);
        return -ENOENT;
    }

    for (i = 0; i < bp->nr_reg_mods; i++)
    {
        if (bp->reg_mods[i].reg_idx == reg_idx)
        {
            bp->reg_mods[i].value = value;
            bp->reg_mods[i].enabled = true;
            ls_log_always_tag("wxshadow", "updated reg mod at %lx: x%d=%lx\n",
                              addr, reg_idx, value);
            wxshadow_page_put(page_info);
            return 0;
        }
    }

    if (bp->nr_reg_mods >= WXSHADOW_MAX_REG_MODS)
    {
        wxshadow_page_put(page_info);
        return -ENOSPC;
    }

    i = bp->nr_reg_mods++;
    bp->reg_mods[i].reg_idx = reg_idx;
    bp->reg_mods[i].value = value;
    bp->reg_mods[i].enabled = true;

    ls_log_always_tag("wxshadow", "added reg mod at %lx: x%d=%lx\n", addr, reg_idx, value);
    wxshadow_page_put(page_info);
    return 0;
}

static int wxshadow_do_patch(struct mm_struct *mm, unsigned long addr,
                             void __user *buf, unsigned long len)
{
    struct wxshadow_write_ctx ctx;
    unsigned long offset = addr & ~PAGE_MASK;
    void *patch_data;
    void *old_patch_data = NULL;
    unsigned long rebuild_len = len;
    int ret;

    ls_log_always_tag("wxshadow", "[patch] addr=%lx len=%lu\n", addr, len);

    if (len == 0 || offset + len > PAGE_SIZE)
    {
        ls_log_always_tag("wxshadow", "[patch] 非法 len=%lu offset=%lu\n", len, offset);
        return -EINVAL;
    }

    /* prctl 场景下 current 就是调用者，普通 copy_from_user 可用 */
    patch_data = kmalloc(len, GFP_KERNEL);
    if (!patch_data)
        return -ENOMEM;

    if (copy_from_user(patch_data, buf, len))
    {
        kfree(patch_data);
        return -EFAULT;
    }

    ret = wxshadow_acquire_write_ctx(mm, addr, "patch", &ctx);
    if (ret < 0)
        goto out_free;

    if (!ctx.is_new)
    {
        ret = wxshadow_upsert_patch_record(ctx.page_info, offset, len, patch_data,
                                           &old_patch_data, &rebuild_len);
        if (ret < 0)
        {
            wxshadow_put_write_ctx(&ctx);
            goto out_free;
        }
        patch_data = NULL; /* 所有权移交页面记录 */

        ret = wxshadow_rebuild_shadow_range(ctx.page_info, offset, rebuild_len);
        if (ret < 0)
        {
            wxshadow_put_write_ctx(&ctx);
            goto out_free;
        }

        ret = wxshadow_activate_write_ctx(&ctx, false);
        if (ret < 0)
        {
            wxshadow_put_write_ctx(&ctx);
            goto out_free;
        }

        if (old_patch_data)
        {
            kfree(old_patch_data);
            old_patch_data = NULL;
        }
        ls_log_always_tag("wxshadow", "[patch] existing shadow %lx+%lx (%lu bytes)\n",
                          ctx.page_addr, offset, len);
        wxshadow_put_write_ctx(&ctx);
        goto out_free;
    }

    ret = wxshadow_prepare_new_write_ctx(&ctx);
    if (ret < 0)
        goto out_free_page;
    ret = wxshadow_upsert_patch_record(ctx.page_info, offset, len, patch_data, NULL, NULL);
    if (ret < 0)
        goto out_free_page;
    patch_data = NULL;

    ret = wxshadow_rebuild_shadow_range(ctx.page_info, offset, len);
    if (ret < 0)
        goto out_free_page;

    ctx.page_info->nr_bps = 0;

    ret = wxshadow_activate_write_ctx(&ctx, true);
    if (ret == 0)
    {
        ls_log_always_tag("wxshadow", "[patch] new shadow %lx+%lx (%lu bytes) pfn %lx->%lx\n",
                          ctx.page_addr, offset, len, ctx.page_info->pfn_original,
                          ctx.page_info->pfn_shadow);
    }
    else
    {
        goto out_free_page;
    }

    wxshadow_put_write_ctx(&ctx);
    kfree(patch_data);
    return 0;

out_free_page:
    wxshadow_abort_write_ctx(&ctx);
out_free:
    if (old_patch_data)
        kfree(old_patch_data);
    kfree(patch_data);
    return ret;
}

static int wxshadow_do_release(struct mm_struct *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    int ret;

    ls_log_always_tag("wxshadow", "[release] addr=%lx\n", addr);

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info)
    {
        ls_log_always_tag("wxshadow", "[release] addr=%lx (page=%lx) 无影子页\n",
                          addr, addr & PAGE_MASK);
        return -ENODATA;
    }

    ret = wxshadow_release_mod_at_addr(page_info, addr,
                                       WXSHADOW_RELEASE_MATCH_BP |
                                       WXSHADOW_RELEASE_MATCH_PATCH,
                                       "user release");
    wxshadow_page_put(page_info);
    return ret;
}

static int wxshadow_do_del_bp(struct mm_struct *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    int ret;

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info)
        return -ENOENT;

    ls_log_always_tag("wxshadow", "del bp at %lx\n", addr);
    ret = wxshadow_release_mod_at_addr(page_info, addr,
                                       WXSHADOW_RELEASE_MATCH_BP,
                                       "last bp removed");
    if (ret == -ENODATA)
        ret = -ENOENT;
    wxshadow_page_put(page_info);
    return ret;
}

/* ========== 读/取指故障处理 ========== */

/* 读故障 -> 切到活动原页 (r--)：完整性校验读到原始代码 */
static int wxshadow_handle_read_fault(struct mm_struct *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    unsigned long page_addr = addr & PAGE_MASK;
    struct vm_area_struct *vma;
    int ret;
    bool should_switch;
    unsigned long flags;

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info)
        return -1;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    should_switch = !page_info->dead &&
                    page_info->state == WX_STATE_SHADOW_X;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    if (!should_switch)
    {
        wxshadow_page_put(page_info);
        return -1;
    }

    vma = find_vma(mm, addr);
    if (!vma || vma->vm_start > addr)
    {
        wxshadow_teardown_page(page_info, "VMA Gone (read fault)");
        wxshadow_page_put(page_info);
        return -1;
    }

    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr))
    {
        wxshadow_teardown_page(page_info, "Mapping Changed (read fault)");
        wxshadow_page_put(page_info);
        return -1;
    }

    ret = wxshadow_page_enter_original(page_info, vma, page_addr);
    if (ret == 0)
        ls_log_always_tag("wxshadow", "read fault at %lx, switched to live original (r--)\n", addr);

    wxshadow_page_put(page_info);
    return ret == 0 ? 0 : -1;
}

/* 取指故障 -> 切回影子页 (--x)；fork 暂停页在这里恢复 */
static int wxshadow_handle_exec_fault(struct mm_struct *mm, unsigned long addr)
{
    struct wxshadow_page *page_info;
    unsigned long page_addr = addr & PAGE_MASK;
    void *shadow_kaddr;
    struct vm_area_struct *vma;
    int ret;
    bool should_switch;
    unsigned long flags;

    page_info = wxshadow_find_page(mm, addr);
    if (!page_info)
        return -1;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    shadow_kaddr = page_info->shadow_page;
    should_switch = !page_info->dead &&
                    page_info->state == WX_STATE_ORIGINAL;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    if (!should_switch)
    {
        wxshadow_page_put(page_info);
        return -1;
    }

    vma = find_vma(mm, addr);
    if (!vma || vma->vm_start > addr)
    {
        wxshadow_teardown_page(page_info, "VMA Gone (exec fault)");
        wxshadow_page_put(page_info);
        return -1;
    }

    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr))
    {
        wxshadow_teardown_page(page_info, "Mapping Changed (exec fault)");
        wxshadow_page_put(page_info);
        return -1;
    }

    /* 影子内容同步到 PoU，再切回影子映射 */
    if (shadow_kaddr)
        arm64_sync_code_range_all_cpus(shadow_kaddr, PAGE_SIZE);

    ret = wxshadow_page_resume_shadow(page_info, vma, page_addr);
    if (ret == 0)
        ls_log_always_tag("wxshadow", "exec fault at %lx, switched to shadow (--x)\n", addr);

    wxshadow_page_put(page_info);
    return ret == 0 ? 0 : -1;
}

/* ========== BRK / 单步 ========== */

static void wxshadow_print_regs(struct pt_regs *regs, unsigned long pc)
{
    ls_log_always_tag("wxshadow", "======== Breakpoint Hit ========\n");
    ls_log_always_tag("wxshadow", "PC=%lx\n", pc);
    ls_log_always_tag("wxshadow", "x0=%016llx x1=%016llx x2=%016llx x3=%016llx\n",
                      (unsigned long long)regs->regs[0], (unsigned long long)regs->regs[1],
                      (unsigned long long)regs->regs[2], (unsigned long long)regs->regs[3]);
    ls_log_always_tag("wxshadow", "x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",
                      (unsigned long long)regs->regs[4], (unsigned long long)regs->regs[5],
                      (unsigned long long)regs->regs[6], (unsigned long long)regs->regs[7]);
    ls_log_always_tag("wxshadow", "x29(fp)=%016llx x30(lr)=%016llx\n",
                      (unsigned long long)regs->regs[29], (unsigned long long)regs->regs[30]);
    ls_log_always_tag("wxshadow", "sp=%016llx pstate=%016llx\n",
                      (unsigned long long)regs->sp, (unsigned long long)regs->pstate);
    ls_log_always_tag("wxshadow", "================================\n");
}

static void wxshadow_apply_reg_mods(struct pt_regs *regs, struct wxshadow_bp *bp)
{
    int i;
    for (i = 0; i < bp->nr_reg_mods; i++)
    {
        struct wxshadow_reg_mod *mod = &bp->reg_mods[i];
        if (!mod->enabled)
            continue;

        if (mod->reg_idx <= 30)
        {
            ls_log_always_tag("wxshadow", "modifying x%d: %016llx -> %016llx\n",
                              mod->reg_idx, (unsigned long long)regs->regs[mod->reg_idx],
                              (unsigned long long)mod->value);
            regs->regs[mod->reg_idx] = mod->value;
        }
        else if (mod->reg_idx == 31)
        {
            ls_log_always_tag("wxshadow", "modifying sp: %016llx -> %016llx\n",
                              (unsigned long long)regs->sp, (unsigned long long)mod->value);
            regs->sp = mod->value;
        }
    }
}

/*
 * 按地址找页（BRK handler 用）。
 * 页在 STEPPING 时自旋等待完成。
 * 返回带引用的页（调用者必须 put），找不到返回 NULL。
 */
static struct wxshadow_page *wxshadow_find_by_addr(struct mm_struct *mm, unsigned long addr)
{
    struct list_head *pos;
    struct wxshadow_page *page_info;
    unsigned long page_addr = addr & PAGE_MASK;
    int retry;
    unsigned long flags;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    list_for_each(pos, &wxshadow_page_list)
    {
        page_info = container_of(pos, struct wxshadow_page, list);

        if (page_info->mm != mm)
            continue;
        if (page_info->page_addr != page_addr)
            continue;
        if (!page_info->pfn_shadow)
            continue;

        if (page_info->state == WX_STATE_SHADOW_X)
        {
            page_info->refcount++;
            spin_unlock_irqrestore(&wxshadow_global_lock, flags);
            return page_info;
        }

        if (page_info->state == WX_STATE_STEPPING)
        {
            retry = 0;
            while (page_info->state == WX_STATE_STEPPING && retry++ < 10000)
            {
                spin_unlock_irqrestore(&wxshadow_global_lock, flags);
                cpu_relax();
                spin_lock_irqsave(&wxshadow_global_lock, flags);
                if (list_empty(&wxshadow_page_list))
                    goto not_found;
            }

            if (page_info->state == WX_STATE_SHADOW_X)
            {
                ls_log_always_tag("wxshadow", "find_by_addr: 等待 STEPPING->SHADOW_X %d 次\n", retry);
                page_info->refcount++;
                spin_unlock_irqrestore(&wxshadow_global_lock, flags);
                return page_info;
            }

            ls_log_always_tag("wxshadow", "find_by_addr: 等待 STEPPING 超时 state=%d\n",
                              page_info->state);
            goto not_found;
        }

        ls_log_always_tag("wxshadow", "find_by_addr: 找到页但 state=%d (需要 SHADOW_X=%d)\n",
                          page_info->state, WX_STATE_SHADOW_X);
    }
not_found:
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
    return NULL;
}

/* 释放后残留 BRK 陷阱：当前映射里已不是 BRK 指令则直接放行 */
static bool wxshadow_can_resume_stale_brk(struct mm_struct *mm, unsigned long pc)
{
    pteval_t pte_val;
    unsigned long pfn;
    void *page_kaddr;
    u32 insn;

    if (wxshadow_read_pte(mm, pc, &pte_val) < 0)
        return false;

    if (!(pte_val & PTE_VALID))
        return false;

    pfn = (pte_val & WXSHADOW_PTE_PFN_MASK) >> PAGE_SHIFT;
    page_kaddr = wxshadow_pfn_to_kaddr(pfn);
    if (!wxshadow_is_kva((unsigned long)page_kaddr))
        return false;

    insn = *(u32 *)((char *)page_kaddr + (pc & ~PAGE_MASK));
    return insn != WXSHADOW_BRK_INSN;
}

static void wxshadow_brk_inflight_put(struct wxshadow_page *page_info)
{
    unsigned long flags;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page_info->brk_in_flight > 0)
        page_info->brk_in_flight--;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);
}

static int wxshadow_brk_handler_impl(struct pt_regs *regs, unsigned int esr)
{
    unsigned long pc = regs->pc;
    unsigned long page_addr = pc & PAGE_MASK;
    struct mm_struct *mm = get_task_mm(current);
    struct vm_area_struct *vma;
    struct wxshadow_page *page_info = NULL;
    struct wxshadow_bp *bp;
    int ret;
    unsigned long flags;

    ls_log_always_tag("wxshadow", "BRK handler ENTER pc=%lx esr=%x mm=%px\n", pc, esr, mm);

    if (!mm)
        return DBG_HOOK_ERROR;

    page_info = wxshadow_find_by_addr(mm, pc);
    if (!page_info)
    {
        if (wxshadow_can_resume_stale_brk(mm, pc))
        {
            ls_log_always_tag("wxshadow", "BRK: stale trap at pc=%lx after release, resume current mapping\n", pc);
            mmput(mm);
            return DBG_HOOK_HANDLED;
        }
        ls_log_always_tag("wxshadow", "BRK: not our breakpoint at pc=%lx\n", pc);
        mmput(mm);
        return DBG_HOOK_ERROR;
    }

    /*
     * exit 循环在 find_by_addr 与这里之间标记 dead 时，不认领 BRK，
     * 让内核正常投递 SIGTRAP（exit 循环正在恢复原 PTE）。
     */
    spin_lock_irqsave(&wxshadow_global_lock, flags);
    if (page_info->dead)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
        wxshadow_page_put(page_info);
        mmput(mm);
        return DBG_HOOK_ERROR;
    }
    page_info->brk_in_flight++;
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    vma = find_vma(mm, pc);
    if (!vma || vma->vm_start > pc)
    {
        wxshadow_brk_inflight_put(page_info);
        wxshadow_teardown_page(page_info, "VMA Gone (BRK handler)");
        wxshadow_page_put(page_info);
        mmput(mm);
        return DBG_HOOK_ERROR;
    }

    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr))
    {
        wxshadow_brk_inflight_put(page_info);
        wxshadow_teardown_page(page_info, "Mapping Changed (BRK handler)");
        wxshadow_page_put(page_info);
        mmput(mm);
        return DBG_HOOK_ERROR;
    }

    bp = wxshadow_find_bp(page_info, pc);
    ret = wxshadow_page_begin_stepping(page_info, vma, page_addr, current);
    if (ret != 0)
    {
        wxshadow_brk_inflight_put(page_info);
        wxshadow_page_put(page_info);
        mmput(mm);
        if (ret == -EBUSY)
        {
            ls_log_always_tag("wxshadow", "BRK: 进入单步时页面已释放 pc=%lx, resume on original mapping\n", pc);
            return DBG_HOOK_HANDLED;
        }
        return DBG_HOOK_ERROR;
    }
    wxshadow_brk_inflight_put(page_info);

    wxshadow_print_regs(regs, pc);

    if (bp && bp->nr_reg_mods > 0)
        wxshadow_apply_reg_mods(regs, bp);

    wxshadow_page_put(page_info);
    mmput(mm);

    if (wxshadow_fn_user_enable_single_step)
        KCALL_1(wxshadow_fn_user_enable_single_step, void, current);
    else
    {
        ls_log_always_tag("wxshadow", "BRK: user_enable_single_step 不可用，无法单步\n");
        return DBG_HOOK_ERROR;
    }

    ls_log_always_tag("wxshadow", "BRK handler EXIT success, single-step enabled\n");
    return DBG_HOOK_HANDLED;
}

static int wxshadow_step_handler_impl(struct pt_regs *regs)
{
    struct mm_struct *mm = get_task_mm(current);
    struct list_head *pos;
    struct wxshadow_page *page_info = NULL;
    struct vm_area_struct *vma;
    int found = 0;
    unsigned long page_addr = 0;
    int ret;
    unsigned long flags;

    if (!mm)
        return DBG_HOOK_ERROR;

    spin_lock_irqsave(&wxshadow_global_lock, flags);
    list_for_each(pos, &wxshadow_page_list)
    {
        page_info = container_of(pos, struct wxshadow_page, list);
        if (page_info->mm != mm)
            continue;

        if (page_info->state == WX_STATE_STEPPING &&
            page_info->stepping_task == current)
        {
            /*
             * BRK handler 置 STEPPING 与到达这里之间 exit 循环标记 dead 时，
             * 跳过切影子页（exit 循环在恢复原映射），只禁用单步。
             */
            if (page_info->dead)
            {
                spin_unlock_irqrestore(&wxshadow_global_lock, flags);
                if (wxshadow_fn_user_disable_single_step)
                    KCALL_1(wxshadow_fn_user_disable_single_step, void, current);
                mmput(mm);
                return DBG_HOOK_HANDLED;
            }
            page_addr = page_info->page_addr;
            page_info->refcount++;
            found = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, flags);

    if (!found)
    {
        ls_log_always_tag("wxshadow", "step handler: NOT FOUND! pc=%llx mm=%px current=%px\n",
                          regs->pc, mm, current);
        mmput(mm);
        return DBG_HOOK_ERROR;
    }

    vma = find_vma(mm, page_addr);

    if (!vma || vma->vm_start > page_addr)
    {
        wxshadow_teardown_page(page_info, "VMA Gone (step handler)");
        wxshadow_page_put(page_info);
        mmput(mm);
        if (wxshadow_fn_user_disable_single_step)
            KCALL_1(wxshadow_fn_user_disable_single_step, void, current);
        return DBG_HOOK_HANDLED;
    }

    if (!wxshadow_validate_page_mapping(mm, vma, page_info, page_addr))
    {
        wxshadow_teardown_page(page_info, "Mapping Changed (step handler)");
        wxshadow_page_put(page_info);
        mmput(mm);
        if (wxshadow_fn_user_disable_single_step)
            KCALL_1(wxshadow_fn_user_disable_single_step, void, current);
        return DBG_HOOK_HANDLED;
    }

    ret = wxshadow_page_finish_stepping(page_info, vma, page_addr, current);
    if (ret < 0)
    {
        ls_log_always_tag("wxshadow", "step: 切回影子页失败 addr=%lx: %d\n", page_addr, ret);
        wxshadow_teardown_page(page_info, "step restore shadow failed");
        wxshadow_page_put(page_info);
        mmput(mm);
        if (wxshadow_fn_user_disable_single_step)
            KCALL_1(wxshadow_fn_user_disable_single_step, void, current);
        return DBG_HOOK_HANDLED;
    }

    if (ret > 0)
        ls_log_always_tag("wxshadow", "step done at pc=%llx, finalized pending release\n", regs->pc);
    else
        ls_log_always_tag("wxshadow", "step done at pc=%llx, switched back to shadow\n", regs->pc);

    wxshadow_page_put(page_info);
    mmput(mm);

    if (wxshadow_fn_user_disable_single_step)
        KCALL_1(wxshadow_fn_user_disable_single_step, void, current);

    return DBG_HOOK_HANDLED;
}

/* ========== fork 保护 ========== */

#define WXSHADOW_FORK_FIX_BATCH 32

struct wxshadow_fork_fix_entry
{
    struct wxshadow_page *page;
    unsigned long page_addr;
};

/*
 * 暂停父进程所有 SHADOW_X 影子映射（切到 ORIGINAL r-- 隐藏页）。
 * copy_process 克隆父页表前调用，子进程因此只继承原始页，避免
 * fork 时 RSS/rmap 把私有影子 PFN 记入账本导致后续 Bad page map。
 * 恢复由取指故障路径完成（wxshadow_page_resume_shadow 里清 fork_paused）。
 */
static void wxshadow_pause_parent_shadow_pages(struct mm_struct *parent_mm)
{
    struct wxshadow_fork_fix_entry batch[WXSHADOW_FORK_FIX_BATCH];
    int nr, i, progress, total_progress = 0;
    struct list_head *pos;
    unsigned long flags;

    do
    {
        nr = 0;
        progress = 0;

        spin_lock_irqsave(&wxshadow_global_lock, flags);
        list_for_each(pos, &wxshadow_page_list)
        {
            struct wxshadow_page *p = container_of(pos, struct wxshadow_page, list);
            if (p->mm == parent_mm && !p->dead &&
                p->state == WX_STATE_SHADOW_X &&
                !p->fork_paused &&
                !p->release_pending &&
                !p->logical_release_pending &&
                p->pfn_original && p->pfn_shadow)
            {
                p->refcount++;
                batch[nr].page = p;
                batch[nr].page_addr = p->page_addr;
                if (++nr >= WXSHADOW_FORK_FIX_BATCH)
                    break;
            }
        }
        spin_unlock_irqrestore(&wxshadow_global_lock, flags);

        if (nr == 0)
            break;

        for (i = 0; i < nr; i++)
        {
            struct wxshadow_page *page = batch[i].page;
            struct vm_area_struct *vma;
            int ret = -1;

            wxshadow_page_pte_lock(page);

            spin_lock_irqsave(&wxshadow_global_lock, flags);
            if (!page->dead &&
                page->state == WX_STATE_SHADOW_X &&
                !page->fork_paused &&
                !page->release_pending &&
                !page->logical_release_pending)
            {
                spin_unlock_irqrestore(&wxshadow_global_lock, flags);

                vma = find_vma(parent_mm, batch[i].page_addr);
                if (vma && vma->vm_start <= batch[i].page_addr)
                {
                    /* 切到 ORIGINAL (r--)，子进程只继承原页 */
                    ret = wxshadow_page_enter_original(page, vma, batch[i].page_addr);
                    if (ret == 0)
                    {
                        spin_lock_irqsave(&wxshadow_global_lock, flags);
                        if (!page->dead && page->state == WX_STATE_ORIGINAL)
                            page->fork_paused = true;
                        spin_unlock_irqrestore(&wxshadow_global_lock, flags);
                        progress++;
                        total_progress++;
                    }
                }
            }
            else
            {
                spin_unlock_irqrestore(&wxshadow_global_lock, flags);
            }

            if (ret != 0)
            {
                ls_log_always_tag("wxshadow", "[fork] pause failed addr=%lx mm=%px: %d\n",
                                  batch[i].page_addr, parent_mm, ret);
            }

            wxshadow_page_pte_unlock(page);
            wxshadow_page_put(batch[i].page);
        }

        if (progress == 0)
            break;

    } while (nr == WXSHADOW_FORK_FIX_BATCH);

    if (total_progress > 0)
        ls_log_always_tag("wxshadow", "[fork] paused %d parent shadow PTEs (mm=%px)\n",
                          total_progress, parent_mm);
}

/* ========== 故障分类 ========== */

#define ESR_ELx_EC_SHIFT 26
#define ESR_ELx_EC_MASK (0x3FUL << ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC(esr) (((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC_UNKNOWN 0x00
#define ESR_ELx_EC_IABT_LOW 0x20
#define ESR_ELx_EC_DABT_LOW 0x24
#define ESR_ELx_WNR_SHIFT 6
#define ESR_ELx_WNR (1UL << ESR_ELx_WNR_SHIFT)
#define ESR_ELx_S1PTW_SHIFT 7
#define ESR_ELx_S1PTW (1UL << ESR_ELx_S1PTW_SHIFT)
#define ESR_ELx_CM_SHIFT 8
#define ESR_ELx_CM (1UL << ESR_ELx_CM_SHIFT)

static inline bool wxshadow_is_el0_instruction_abort(unsigned int esr)
{
    return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
}

static inline bool wxshadow_is_el0_data_abort(unsigned int esr)
{
    return ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW;
}

static inline bool wxshadow_is_permission_fault(unsigned int esr)
{
    unsigned int fsc = esr & 0x3F;
    return (fsc & 0x3C) == 0x0C;
}

enum wxshadow_fault_access
{
    WXSHADOW_FAULT_NONE = 0,
    WXSHADOW_FAULT_EXEC,
    WXSHADOW_FAULT_READ,
    WXSHADOW_FAULT_WRITE,
};

static inline enum wxshadow_fault_access
wxshadow_classify_permission_fault(unsigned int esr)
{
    if (!wxshadow_is_permission_fault(esr))
        return WXSHADOW_FAULT_NONE;

    if (wxshadow_is_el0_instruction_abort(esr))
        return WXSHADOW_FAULT_EXEC;

    if (!wxshadow_is_el0_data_abort(esr))
        return WXSHADOW_FAULT_NONE;

    /* CM 视为读侧（翻转回原页），S1PTW 忽略 */
    if (esr & ESR_ELx_S1PTW)
        return WXSHADOW_FAULT_NONE;
    if (esr & ESR_ELx_CM)
        return WXSHADOW_FAULT_READ;

    return (esr & ESR_ELx_WNR) ? WXSHADOW_FAULT_WRITE
                               : WXSHADOW_FAULT_READ;
}

/* ========== inline hook work_fn（lsdriver 框架） ========== */

/*
 * 注意：lsdriver 的 work_fn 收到的是跳板构造的合成 pt_regs：
 *   regs[0..7] = 目标函数前 8 个参数（x0-x7）
 * 返回 0 = 回放原指令继续原函数；返回 1 = 跳过原函数
 * （跳过时 hook_regs->regs[0] 作为返回值写回 x0）。
 */

/* brk_handler(unsigned long esr, struct pt_regs *regs) */
static int wxshadow_brk_work(struct pt_regs *hook_regs)
{
    unsigned int esr = (unsigned int)hook_regs->regs[0];
    struct pt_regs *regs = (struct pt_regs *)hook_regs->regs[1];
    u16 imm = (u16)(esr & 0xFFFF); /* BRK ISS 低 16 位是 imm16 */

    if (!user_mode(regs))
        return 0;

    if (imm != WXSHADOW_BRK_IMM)
        return 0;

    if (wxshadow_brk_handler_impl(regs, esr) == DBG_HOOK_HANDLED)
        return 1;

    return 0;
}

/* single_step_handler(unsigned long esr, struct pt_regs *regs) */
static int wxshadow_step_work(struct pt_regs *hook_regs)
{
    struct pt_regs *regs = (struct pt_regs *)hook_regs->regs[1];

    if (!user_mode(regs))
        return 0;

    if (wxshadow_step_handler_impl(regs) == DBG_HOOK_HANDLED)
        return 1;

    return 0;
}

/* do_page_fault(unsigned long far, unsigned int esr, struct pt_regs *regs) */
static int wxshadow_fault_work(struct pt_regs *hook_regs)
{
    unsigned long far = (unsigned long)hook_regs->regs[0];
    unsigned int esr = (unsigned int)hook_regs->regs[1];
    enum wxshadow_fault_access access;
    struct mm_struct *mm;
    struct wxshadow_page *page;

    /* 快路径：没有影子页时零开销放行 */
    if (list_empty(&wxshadow_page_list))
        return 0;

    mm = get_task_mm(current);
    if (!mm)
        return 0;

    access = wxshadow_classify_permission_fault(esr);
    if (access == WXSHADOW_FAULT_NONE)
    {
        mmput(mm);
        return 0;
    }

    page = wxshadow_find_page(mm, far);
    if (!page)
    {
        mmput(mm);
        return 0;
    }

    if (access == WXSHADOW_FAULT_EXEC)
    {
        if (wxshadow_handle_exec_fault(mm, far) == 0)
        {
            hook_regs->regs[0] = 0; /* 处理成功，返回 0 */
            wxshadow_page_put(page);
            mmput(mm);
            return 1; /* 跳过原 do_page_fault，重试故障指令 */
        }
    }
    else if (access == WXSHADOW_FAULT_READ)
    {
        if (wxshadow_handle_read_fault(mm, far) == 0)
        {
            hook_regs->regs[0] = 0;
            wxshadow_page_put(page);
            mmput(mm);
            return 1;
        }
    }
    else
    {
        /* 写故障：自动逻辑释放 */
        wxshadow_handle_write_fault(mm, far);
    }

    wxshadow_page_put(page);
    mmput(mm);
    return 0;
}

/*
 * shadow_memory.h（同编译单元，lsdriver.c 先于本文件 include）的影子页清理。
 * 两个影子页系统共用同一个 exit_mmap hook，避免同目标双 hook。
 */
static void ls_shadow_release_mm(struct mm_struct *mm);

/* exit_mmap(struct mm_struct *mm) */
static int wxshadow_exit_mmap_work(struct pt_regs *hook_regs)
{
    struct mm_struct *mm = (struct mm_struct *)hook_regs->regs[0];
    int nr;

    if (!mm)
        return 0;

    /* 先清 shadow_memory.h 的影子页，再清 wxshadow 的影子页 */
    ls_shadow_release_mm(mm);

    nr = wxshadow_teardown_pages_for_mm(mm, "exit_mmap");
    if (nr > 0)
        ls_log_always_tag("wxshadow", "[exit_mmap] cleaned %d pages for mm=%px\n", nr, mm);

    return 0; /* 继续原 exit_mmap */
}

/*
 * follow_page_pte(struct vm_area_struct *vma, unsigned long address, pmd_t *pmd,
 *                 unsigned int flags, struct dev_pagemap **pgmap)
 *
 * GUP 隐藏（/proc/pid/mem、process_vm_readv、ptrace）：
 * lsdriver 框架只有 before 型 work_fn，没有 after 钩子，因此采用
 * "切原页 + 广播刷 TLB + 状态回 ORIGINAL" 的变体：follow_page_pte 读到的
 * PTE 是原始页；目标进程下次取指会触发权限故障，由取指故障路径自动切回
 * 影子页。代价是每次 GUP 读取后目标进程多一次取指故障。
 */
static int wxshadow_follow_page_pte_work(struct pt_regs *hook_regs)
{
    struct vm_area_struct *vma = (struct vm_area_struct *)hook_regs->regs[0];
    unsigned long address = (unsigned long)hook_regs->regs[1];
    unsigned int flags = (unsigned int)hook_regs->regs[3];
    struct mm_struct *mm;
    struct wxshadow_page *page;
    struct vm_area_struct *cur_vma;
    unsigned long irq_flags;

    /* 快路径 */
    if (list_empty(&wxshadow_page_list))
        return 0;

    /* 只拦截读 */
    if (flags & 0x01) /* FOLL_WRITE */
        return 0;

    if (!vma)
        return 0;
    mm = vma->vm_mm;
    if (!mm)
        return 0;

    page = wxshadow_find_page(mm, address);
    if (!page)
        return 0;

    spin_lock_irqsave(&wxshadow_global_lock, irq_flags);
    if (page->dead || page->state != WX_STATE_SHADOW_X ||
        page->logical_release_pending || !page->pfn_original)
    {
        spin_unlock_irqrestore(&wxshadow_global_lock, irq_flags);
        wxshadow_page_put(page);
        return 0;
    }
    spin_unlock_irqrestore(&wxshadow_global_lock, irq_flags);

    wxshadow_page_pte_lock(page);

    cur_vma = find_vma(mm, page->page_addr);
    if (!cur_vma || cur_vma->vm_start > page->page_addr)
    {
        wxshadow_page_pte_unlock(page);
        wxshadow_page_put(page);
        return 0;
    }

    /* 切到隐藏原页 (r-- + UXN)，刷 TLB，状态回 ORIGINAL */
    if (wxshadow_page_enter_original(page, cur_vma, page->page_addr) == 0)
        ls_log_always_tag("wxshadow", "GUP hide at %lx, switched to original (r--)\n", address);

    wxshadow_page_pte_unlock(page);
    wxshadow_page_put(page);

    return 0; /* 继续原 follow_page_pte */
}

/* dup_mmap(struct mm_struct *oldmm, struct mm_struct *mm) —— fork 保护 */
static int wxshadow_dup_mmap_work(struct pt_regs *hook_regs)
{
    struct mm_struct *oldmm = (struct mm_struct *)hook_regs->regs[0];

    if (!oldmm)
        return 0;

    wxshadow_pause_parent_shadow_pages(oldmm);
    return 0; /* 继续原 dup_mmap，子进程继承原页 */
}

/* ========== prctl 接口 ========== */

static struct mm_struct *wxshadow_resolve_pid_to_mm(pid_t pid)
{
    if (pid == 0)
        return get_task_mm(current);

    return get_mm_by_pid(pid);
}

static int wxshadow_prctl_handle(struct pt_regs *hook_regs, long option,
                                 unsigned long arg2, unsigned long arg3,
                                 unsigned long arg4, unsigned long arg5)
{
    struct mm_struct *mm;
    pid_t pid;
    long ret;

    /* 只处理 wxshadow 命令范围 */
    if (option < PR_WXSHADOW_SET_BP || option > PR_WXSHADOW_RELEASE)
        return 0;

    switch (option)
    {
    case PR_WXSHADOW_SET_BP:
        pid = (pid_t)arg2;
        mm = wxshadow_resolve_pid_to_mm(pid);
        if (!mm)
        {
            ret = -ESRCH;
            break;
        }
        ret = wxshadow_do_set_bp(mm, arg3);
        mmput(mm);
        break;

    case PR_WXSHADOW_SET_REG:
        pid = (pid_t)arg2;
        mm = wxshadow_resolve_pid_to_mm(pid);
        if (!mm)
        {
            ret = -ESRCH;
            break;
        }
        ret = wxshadow_do_set_reg(mm, arg3, (unsigned int)arg4, arg5);
        mmput(mm);
        break;

    case PR_WXSHADOW_DEL_BP:
        pid = (pid_t)arg2;
        mm = wxshadow_resolve_pid_to_mm(pid);
        if (!mm)
        {
            ret = -ESRCH;
            break;
        }
        if (arg3 == 0)
            ret = wxshadow_release_pages_for_mm(mm, "del_all_bp");
        else
            ret = wxshadow_do_del_bp(mm, arg3);
        mmput(mm);
        break;

    case PR_WXSHADOW_SET_TLB_MODE:
        if (arg2 > WX_TLB_MODE_FULL)
        {
            ls_log_always_tag("wxshadow", "[prctl] 非法 TLB mode: %lu\n", arg2);
            ret = -EINVAL;
        }
        else
        {
            int old_mode = wxshadow_tlb_flush_mode;

            wxshadow_tlb_flush_mode = (int)arg2;
            ls_log_always_tag("wxshadow", "[prctl] TLB mode changed: %d -> %d\n",
                              old_mode, wxshadow_tlb_flush_mode);
            ret = 0;
        }
        break;

    case PR_WXSHADOW_GET_TLB_MODE:
        ret = wxshadow_tlb_flush_mode;
        break;

    case PR_WXSHADOW_PATCH:
        pid = (pid_t)arg2;
        mm = wxshadow_resolve_pid_to_mm(pid);
        if (!mm)
        {
            ret = -ESRCH;
            break;
        }
        ret = wxshadow_do_patch(mm, arg3, (void __user *)arg4, arg5);
        mmput(mm);
        break;

    case PR_WXSHADOW_RELEASE:
        pid = (pid_t)arg2;
        mm = wxshadow_resolve_pid_to_mm(pid);
        if (!mm)
        {
            ret = -ESRCH;
            break;
        }
        if (arg3 == 0)
            ret = wxshadow_release_pages_for_mm(mm, "release_all");
        else
            ret = wxshadow_do_release(mm, arg3);
        mmput(mm);
        break;

    default:
        return 0;
    }

    /* 覆盖 x0 = syscall 返回值，跳过原始 prctl */
    hook_regs->regs[0] = (uint64_t)ret;
    return 1;
}

/* __arm64_sys_prctl(const struct pt_regs *regs)：x0 是用户 syscall 现场指针 */
static int wxshadow_prctl_arm64_work(struct pt_regs *hook_regs)
{
    struct pt_regs *user_regs = (struct pt_regs *)hook_regs->regs[0];

    if (!user_regs || !wxshadow_is_kva((unsigned long)user_regs))
        return 0;

    return wxshadow_prctl_handle(hook_regs,
                                 user_regs->regs[0],
                                 user_regs->regs[1],
                                 user_regs->regs[2],
                                 user_regs->regs[3],
                                 user_regs->regs[4]);
}

/* __se_sys_prctl(option, arg2, arg3, arg4, arg5)：参数直接在当前寄存器 */
static int wxshadow_prctl_direct_work(struct pt_regs *hook_regs)
{
    return wxshadow_prctl_handle(hook_regs,
                                 (long)hook_regs->regs[0],
                                 hook_regs->regs[1],
                                 hook_regs->regs[2],
                                 hook_regs->regs[3],
                                 hook_regs->regs[4]);
}

/* ========== hook 表与安装 ========== */

/*
 * 必需 hook：任一失败则初始化失败。
 * brk/single_step 是无痕断点的核心链路；exit_mmap 保证进程退出时影子页
 * 安全清理（没有它退出时会踩 Bad page map）。
 */
static struct hook_entry g_wxshadow_required_hooks[] = {
    HOOK_ENTRY("brk_handler", wxshadow_brk_work),
    HOOK_ENTRY("single_step_handler", wxshadow_step_work),
    HOOK_ENTRY("exit_mmap", wxshadow_exit_mmap_work),
};

/*
 * 可选 hook：单个符号不存在时降级（逐条安装，失败只告警不影响加载）。
 * do_page_fault    -> 读/取指故障隐藏（核心隐藏能力，建议保留）
 * follow_page_pte  -> GUP 隐藏（/proc/pid/mem、process_vm_readv、ptrace）
 * dup_mmap         -> fork 保护（子进程不继承影子页）
 */
static struct hook_entry g_wxshadow_optional_hooks[] = {
    HOOK_ENTRY("do_page_fault", wxshadow_fault_work),
    HOOK_ENTRY("follow_page_pte", wxshadow_follow_page_pte_work),
    HOOK_ENTRY("dup_mmap", wxshadow_dup_mmap_work),
};

/* prctl 双符号逐个尝试（gnss 风格）：__arm64_sys_prctl 优先，失败回退 __se_sys_prctl */
static struct hook_entry g_wxshadow_prctl_targets[][1] = {
    {HOOK_ENTRY("__arm64_sys_prctl", wxshadow_prctl_arm64_work)},
    {HOOK_ENTRY("__se_sys_prctl", wxshadow_prctl_direct_work)},
};

static int wxshadow_prctl_hook_install(void)
{
    int ret = -ENOENT;

    for (int i = 0; i < (int)ARRAY_SIZE(g_wxshadow_prctl_targets); i++)
    {
        ret = inline_hook_install(g_wxshadow_prctl_targets[i]);
        if (!ret)
        {
            ls_log_always_tag("wxshadow", "prctl hook on %s registered\n",
                              g_wxshadow_prctl_targets[i][0].target_sym);
            return 0;
        }
        ls_log_always_tag("wxshadow", "prctl hook on %s failed: %d\n",
                          g_wxshadow_prctl_targets[i][0].target_sym, ret);
    }

    return ret;
}

static void wxshadow_prctl_hook_remove(void)
{
    for (int i = 0; i < (int)ARRAY_SIZE(g_wxshadow_prctl_targets); i++)
        inline_hook_remove(g_wxshadow_prctl_targets[i]);
}

/*
 * 模块初始化时调用（lsdriver_init -> wxshadow_hook_init）。
 * 必需 hook 失败则回滚已安装的项并返回错误；可选 hook 失败仅降级。
 */
static int wxshadow_hook_init(void)
{
    int ret;
    int i;

    wxshadow_resolve_symbols();

    /* 单步函数是无痕断点的必需依赖（BRK 命中后靠它步过原始指令） */
    if (!wxshadow_fn_user_enable_single_step || !wxshadow_fn_user_disable_single_step)
    {
        ls_log_always_tag("wxshadow", "user_enable/disable_single_step 缺失，拒绝加载\n");
        return -ENOSYS;
    }

    ret = inline_hook_install(g_wxshadow_required_hooks);
    if (ret < 0)
    {
        ls_log_always_tag("wxshadow", "required hooks install failed: %d\n", ret);
        return ret;
    }

    for (i = 0; i < (int)ARRAY_SIZE(g_wxshadow_optional_hooks); i++)
    {
        ret = inline_hook_install(&g_wxshadow_optional_hooks[i]);
        if (ret < 0)
            ls_log_always_tag("wxshadow", "optional hook %s install failed: %d (feature degraded)\n",
                              g_wxshadow_optional_hooks[i].target_sym, ret);
        else
            ls_log_always_tag("wxshadow", "optional hook %s registered\n",
                              g_wxshadow_optional_hooks[i].target_sym);
    }

    ret = wxshadow_prctl_hook_install();
    if (ret < 0)
    {
        ls_log_always_tag("wxshadow", "prctl hook install failed: %d, rollback\n", ret);
        for (i = 0; i < (int)ARRAY_SIZE(g_wxshadow_optional_hooks); i++)
            inline_hook_remove(&g_wxshadow_optional_hooks[i]);
        inline_hook_remove(g_wxshadow_required_hooks);
        return ret;
    }

    ls_log_always_tag("wxshadow", "W^X shadow memory hook loaded\n");
    ls_log_always_tag("wxshadow", "use prctl(0x%x, pid, addr) to set breakpoint\n", PR_WXSHADOW_SET_BP);
    return 0;
}

/* 清理：拆全部影子页 + 卸载 wxshadow 的 hook（幂等，可重复调用） */
static void __maybe_unused wxshadow_hook_exit(void)
{
    wxshadow_prctl_hook_remove();
    for (int i = 0; i < (int)ARRAY_SIZE(g_wxshadow_optional_hooks); i++)
        inline_hook_remove(&g_wxshadow_optional_hooks[i]);
    inline_hook_remove(g_wxshadow_required_hooks);
    wxshadow_teardown_pages_for_mm(NULL, "module unload");
}

#endif /* _LSDRIVER_WXSHADOW_HOOK_H_ */
