/*
 * lsdriver.h - lsdriver 内核驱动用户态 API 封装
 *
 * 通信协议与内核侧 lsdriver/io_struct.h 完全一致（固定地址共享内存）：
 *   1. prctl(PR_SET_NAME, "LS") 把进程名设置为 LS
 *   2. mmap 固定地址 0x2025827000 创建 sizeof(request_obj) 共享内存
 *   3. 清零后提交 op，等待 req->user 置位即完成一次请求
 *
 * 用法：
 *   if (ls_connect() < 0) { ... }
 *   pid_t pid = ls_find_pid_by_name("com.tencent.tmgp.sgame");
 *   uint32_t v = 0;
 *   ls_read(pid, addr, &v, sizeof(v));
 *
 * 交叉编译：aarch64-linux-gnu-gcc -O2 -static -o demo demo.c lsdriver.h
 *
 * 注意：struct request_obj 必须与内核 io_struct.h 保持逐字段一致，
 *       修改任一侧时同步另一侧。
 */
#ifndef LSDRIVER_H
#define LSDRIVER_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========== 与 lsdriver/io_struct.h 一致的共享结构 ========== */

#define LS_SHARED_MEM_ADDR 0x2025827000UL /* 固定共享内存地址（驱动约定） */
#define LS_PROCESS_NAME    "LS"           /* 驱动识别的进程名 */

#define TLS_THREAD_NAME_LEN 16
struct ls_env_params
{
    char thread_name[TLS_THREAD_NAME_LEN];
    uint64_t tpidr_el0;
    uint64_t pacga_lo;
    uint64_t pacga_hi;
    int tls_status;
    int pacga_status;
};

#define BP_OP_NONE 0x0
#define BP_OP_READ 0x1
#define BP_OP_WRITE 0x2
#define BP_CONFIG_MAX 16
#define BP_RECORD_MAX 0x10

#define BP_SET_MASK(record, reg, op)                            \
    do                                                          \
    {                                                           \
        int byte_idx = (reg) >> 2;                              \
        int bit_offset = ((reg) & 0x3) << 1;                    \
        (record)->mask[byte_idx] &= ~(0x3 << bit_offset);       \
        (record)->mask[byte_idx] |= ((op) & 0x3) << bit_offset; \
    } while (0)

#define BP_GET_MASK(record, reg) (((record)->mask[(reg) >> 2] >> (((reg) & 0x3) << 1)) & 0x3)

enum ls_bp_type
{
    BP_BREAKPOINT_EMPTY = 0,
    BP_BREAKPOINT_R = 1,
    BP_BREAKPOINT_W = 2,
    BP_BREAKPOINT_RW = BP_BREAKPOINT_R | BP_BREAKPOINT_W,
    BP_BREAKPOINT_X = 4,
    BP_BREAKPOINT_INVALID = BP_BREAKPOINT_RW | BP_BREAKPOINT_X,
};
enum ls_bp_len
{
    BP_BREAKPOINT_LEN_1 = 1,
    BP_BREAKPOINT_LEN_2 = 2,
    BP_BREAKPOINT_LEN_3 = 3,
    BP_BREAKPOINT_LEN_4 = 4,
    BP_BREAKPOINT_LEN_5 = 5,
    BP_BREAKPOINT_LEN_6 = 6,
    BP_BREAKPOINT_LEN_7 = 7,
    BP_BREAKPOINT_LEN_8 = 8,
};
enum ls_bp_scope
{
    BP_SCOPE_MAIN_THREAD,
    BP_SCOPE_OTHER_THREADS,
    BP_SCOPE_ALL_THREADS
};

enum ls_bp_reg_idx
{
    IDX_PC = 0,
    IDX_HIT_COUNT,
    IDX_LR,
    IDX_SP,
    IDX_ORIG_X0,
    IDX_SYSCALLNO,
    IDX_PSTATE,
    IDX_X0,
    IDX_X1,
    IDX_X2,
    IDX_X3,
    IDX_X4,
    IDX_X5,
    IDX_X6,
    IDX_X7,
    IDX_X8,
    IDX_X9,
    IDX_X10,
    IDX_X11,
    IDX_X12,
    IDX_X13,
    IDX_X14,
    IDX_X15,
    IDX_X16,
    IDX_X17,
    IDX_X18,
    IDX_X19,
    IDX_X20,
    IDX_X21,
    IDX_X22,
    IDX_X23,
    IDX_X24,
    IDX_X25,
    IDX_X26,
    IDX_X27,
    IDX_X28,
    IDX_X29,
    IDX_FPSR,
    IDX_FPCR,
    IDX_Q0,
    IDX_Q1,
    IDX_Q2,
    IDX_Q3,
    IDX_Q4,
    IDX_Q5,
    IDX_Q6,
    IDX_Q7,
    IDX_Q8,
    IDX_Q9,
    IDX_Q10,
    IDX_Q11,
    IDX_Q12,
    IDX_Q13,
    IDX_Q14,
    IDX_Q15,
    IDX_Q16,
    IDX_Q17,
    IDX_Q18,
    IDX_Q19,
    IDX_Q20,
    IDX_Q21,
    IDX_Q22,
    IDX_Q23,
    IDX_Q24,
    IDX_Q25,
    IDX_Q26,
    IDX_Q27,
    IDX_Q28,
    IDX_Q29,
    IDX_Q30,
    IDX_Q31,
    MAX_REG_COUNT
};

struct ls_bp_record
{
    uint8_t mask[18];
    uint64_t hit_count;
    uint64_t pc;
    uint64_t lr;
    uint64_t sp;
    uint64_t orig_x0;
    int32_t syscallno;
    uint64_t pstate;
    uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9;
    uint64_t x10, x11, x12, x13, x14, x15, x16, x17, x18, x19;
    uint64_t x20, x21, x22, x23, x24, x25, x26, x27, x28, x29;
    uint32_t fpsr;
    uint32_t fpcr;
    __uint128_t q0, q1, q2, q3, q4, q5, q6, q7, q8, q9;
    __uint128_t q10, q11, q12, q13, q14, q15, q16, q17, q18, q19;
    __uint128_t q20, q21, q22, q23, q24, q25, q26, q27, q28, q29;
    __uint128_t q30, q31;
};

struct ls_bp_point
{
    void (*on_hit)(void *regs, void *fp_regs, void *hit_point);
    enum ls_bp_type bt;
    enum ls_bp_len bl;
    enum ls_bp_scope bs;
    uint64_t hit_addr;
    int record_count;
    struct ls_bp_record records[BP_RECORD_MAX];
};

struct ls_break_point
{
    uint64_t num_brps;
    uint64_t num_wrps;
    int tgid;
    struct ls_bp_point points[BP_CONFIG_MAX];
};

struct ls_virtual_gnss
{
    int latitude_e7;
    int longitude_e7;
};

struct ls_virtual_gyro
{
    int gyro_x_mrad_s;
    int gyro_y_mrad_s;
    int gyro_z_mrad_s;
};

struct ls_virtual_input
{
    int request_virtual_slots;
    int POSITION_X, POSITION_Y;
    int slot;
    int x, y;
};

#define LS_MAX_MODULES 1024
#define LS_MAX_SCAN_REGIONS 16534
#define LS_MOD_NAME_LEN 256
#define LS_MAX_SEGS_PER_MODULE 512

struct ls_segment_info
{
    short index;
    uint8_t prot; /* 1(R) 2(W) 4(X)，例如 RX=5 */
    uint64_t start;
    uint64_t end;
};

struct ls_module_info
{
    char name[LS_MOD_NAME_LEN];
    int seg_count;
    struct ls_segment_info segs[LS_MAX_SEGS_PER_MODULE];
};

struct ls_region_info
{
    uint64_t start;
    uint64_t end;
};

struct ls_virtual_memory
{
    int module_count;
    struct ls_module_info modules[LS_MAX_MODULES];
    int region_count;
    struct ls_region_info regions[LS_MAX_SCAN_REGIONS];
};

struct ls_virtual_memoryrw
{
    uint64_t rw_addr;
    uint8_t user_buffer[0x1000];
    int size;
};

enum request_op
{
    request_op_none,
    request_op_vmem_read,
    request_op_vmem_write,
    request_op_vmem_info,

    request_op_touch_init,
    request_op_touch_down,
    request_op_touch_move,
    request_op_touch_up,

    request_op_gyro_init,
    request_op_gyro_report,

    request_op_gnss_init,
    request_op_gnss_report,

    request_op_hwbp_set,
    request_op_hwbp_remove,

    request_op_ptebp_set,
    request_op_ptebp_remove,

    request_op_stepbp_set,
    request_op_stepbp_remove,

    request_op_syscall_monitor_set,
    request_op_syscall_monitor_remove,

    request_op_cntvct_monitor_set,
    request_op_cntvct_monitor_remove,

    request_op_env_get_params,

    request_op_kernel_exit,
};

struct request_obj
{
    volatile bool kernel;
    volatile bool user;
    volatile enum request_op op;
    volatile int status;

    int tgid;

    struct ls_virtual_memoryrw vmemrw_info;
    struct ls_virtual_memory vmem_info;
    struct ls_virtual_input vinput_info;
    struct ls_virtual_gyro vgyro_info;
    struct ls_virtual_gnss vgnss_info;
    struct ls_break_point bp_info;
    struct ls_env_params env_info;
};

/* ========== 连接与请求 ========== */

static struct request_obj *g_req = NULL;

/* 提交一次请求并等待内核处理完成，返回 req->status */
static inline int ls_io_commit(void)
{
    if (!g_req)
        return -EIO;

    g_req->kernel = true;
    asm volatile("dmb ish" ::: "memory");

    /*
     * 先忙等（驱动处理完直接写共享内存 user 标志，忙等可微秒级感知），
     * 超过约 3000 次 yield 再 usleep 短睡兜底，避免长时间空转。
     * 相比固定 usleep(100)，单次往返延迟从 ~150-200us 降到 ~20-60us。
     */
    int spins = 0;
    while (!g_req->user)
    {
        if (++spins <= 3000)
            asm volatile("yield" ::: "memory");
        else
            usleep(20);
    }

    asm volatile("dmb ish" ::: "memory");
    g_req->user = false;
    return g_req->status;
}

/*
 * 连接 lsdriver 驱动：
 *   1. 进程名设置为 LS
 *   2. mmap 固定地址共享内存
 *   3. 提交空操作等待驱动握手
 * 返回 0 成功；连接前驱动需要已加载且连接线程在轮询（驱动默认每 2 秒扫描一次）。
 */
static inline int ls_connect(void)
{
    if (g_req)
        return 0;

    if (prctl(PR_SET_NAME, LS_PROCESS_NAME, 0, 0, 0) < 0)
        return -errno;

    void *p = mmap((void *)LS_SHARED_MEM_ADDR, sizeof(struct request_obj),
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED)
        return -errno;

    memset(p, 0, sizeof(struct request_obj));
    g_req = (struct request_obj *)p;

    /* 握手：驱动连接线程找到 LS 进程后会 vmap 同一块内存并置 req->user */
    g_req->op = request_op_none;
    int ret = ls_io_commit();
    if (ret < 0)
    {
        munmap(p, sizeof(struct request_obj));
        g_req = NULL;
        return ret;
    }
    return 0;
}

/* ========== 进程内存读写（自动分片，单次 ≤ 0x1000 字节） ========== */

/*
 * 读目标进程内存。返回实际读取字节数（>0），失败返回负 errno。
 * 大块读取时失败页跳过并清零，只要成功处理过字节就返回成功字节数。
 */
static inline int ls_read(pid_t pid, uint64_t addr, void *buf, size_t size)
{
    if (!g_req || !buf)
        return -EINVAL;

    int total = 0;
    while (size > 0)
    {
        size_t chunk = size > 0x1000 ? 0x1000 : size;

        g_req->op = request_op_vmem_read;
        g_req->tgid = pid;
        g_req->vmemrw_info.rw_addr = addr;
        g_req->vmemrw_info.size = (int)chunk;
        int ret = ls_io_commit();
        if (ret < 0)
            return total > 0 ? total : ret;
        if (ret > 0)
            memcpy((char *)buf + total, g_req->vmemrw_info.user_buffer, (size_t)ret);
        else
            memset((char *)buf + total, 0, chunk); /* 失败页清零 */

        total += (int)chunk;
        addr += chunk;
        buf = (char *)buf + chunk;
        size -= chunk;
    }
    return total;
}

/* 写目标进程内存，返回实际写入字节数（>0），失败返回负 errno */
static inline int ls_write(pid_t pid, uint64_t addr, const void *buf, size_t size)
{
    if (!g_req || !buf)
        return -EINVAL;

    int total = 0;
    while (size > 0)
    {
        size_t chunk = size > 0x1000 ? 0x1000 : size;

        g_req->op = request_op_vmem_write;
        g_req->tgid = pid;
        g_req->vmemrw_info.rw_addr = addr;
        g_req->vmemrw_info.size = (int)chunk;
        memcpy(g_req->vmemrw_info.user_buffer, (const char *)buf + total, chunk);
        int ret = ls_io_commit();
        if (ret < 0)
            return total > 0 ? total : ret;

        total += (int)chunk;
        addr += chunk;
        size -= chunk;
    }
    return total;
}

/* 便捷模板：读/写基础类型 */
#define LS_READ(pid, addr, val) ls_read((pid), (addr), (val), sizeof(*(val)))
#define LS_WRITE(pid, addr, val) ls_write((pid), (addr), (val), sizeof(*(val)))

/* ========== 内存布局枚举 ========== */

/*
 * 枚举目标进程模块与扫描区域。
 * mem 由调用者提供，返回后 module_count/region_count 有效。
 */
static inline int ls_get_memory_info(pid_t pid, struct ls_virtual_memory *mem)
{
    if (!g_req || !mem)
        return -EINVAL;

    g_req->op = request_op_vmem_info;
    g_req->tgid = pid;
    int ret = ls_io_commit();
    if (ret < 0)
        return ret;
    memcpy(mem, &g_req->vmem_info, sizeof(*mem));
    return 0;
}

/*
 * 按模块名后缀查找模块基址（取第一个非空段起点）。
 * 找不到返回 0。
 */
static inline uint64_t ls_get_module_address(pid_t pid, const char *name_suffix)
{
    /* DroidC 等 C++ 模式编译需要显式强转 void* */
    struct ls_virtual_memory *mem = (struct ls_virtual_memory *)malloc(sizeof(*mem));
    if (!mem)
        return 0;

    uint64_t base = 0;
    if (ls_get_memory_info(pid, mem) == 0)
    {
        for (int i = 0; i < mem->module_count; i++)
        {
            if (strstr(mem->modules[i].name, name_suffix))
            {
                for (int s = 0; s < mem->modules[i].seg_count; s++)
                {
                    if (mem->modules[i].segs[s].start)
                    {
                        base = mem->modules[i].segs[s].start;
                        break;
                    }
                }
                break;
            }
        }
    }
    free(mem);
    return base;
}

/* ========== 硬件断点 / 观察点 ========== */

/*
 * 设置硬件断点/观察点（arm64_hwdbg）。
 *   type: BP_BREAKPOINT_R / W / RW / X
 *   len:  BP_BREAKPOINT_LEN_1..8
 * 命中记录写入 bp->points[0].records（按 PC 聚合）。
 */
static inline int ls_hwbp_set(pid_t pid, uint64_t addr, enum ls_bp_type type,
                              enum ls_bp_len len, struct ls_break_point *bp)
{
    if (!g_req || !bp)
        return -EINVAL;

    memset(bp, 0, sizeof(*bp));
    bp->tgid = pid;
    bp->points[0].bt = type;
    bp->points[0].bl = len;
    bp->points[0].bs = BP_SCOPE_ALL_THREADS;
    bp->points[0].hit_addr = addr;

    memcpy(&g_req->bp_info, bp, sizeof(*bp));
    g_req->op = request_op_hwbp_set;
    g_req->tgid = pid;
    int ret = ls_io_commit();
    memcpy(bp, &g_req->bp_info, sizeof(*bp));
    return ret;
}

static inline int ls_hwbp_remove(void)
{
    if (!g_req)
        return -EINVAL;

    g_req->op = request_op_hwbp_remove;
    return ls_io_commit();
}

/* ========== 进程查找 ========== */

/*
 * 遍历 /proc 按 cmdline 匹配包名/进程名，返回 pid；找不到返回 -1。
 */
static inline pid_t ls_find_pid_by_name(const char *name)
{
    DIR *dir = opendir("/proc");
    if (!dir)
        return -1;

    pid_t found = -1;
    struct dirent *ent;
    char path[64];
    char buf[512];

    while ((ent = readdir(dir)) != NULL)
    {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
            continue;

        snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0)
            continue;
        buf[n] = '\0';

        if (strstr(buf, name))
        {
            found = (pid_t)atoi(ent->d_name);
            break;
        }
    }
    closedir(dir);
    return found;
}

/* ========== wxshadow 无痕 hook（W^X Shadow Memory） ========== */

/*
 * 无痕隐藏断点：在目标进程代码页创建影子页，断点写进影子页。
 * 进程读取（完整性校验/扫描）时映射到原始页，永远读到原始指令；
 * 执行到断点地址时映射到影子页，触发 BRK（真正"无痕"的 hook）。
 *
 * 命中后现场（PC/寄存器）由驱动打印到内核日志：
 *   dmesg | grep wxshadow
 *
 * 命中时可通过 ls_wxshadow_set_reg 修改寄存器（如把写入字段的源寄存器
 * 改成指定值，实现"hook 改字段"）。
 */

#define PR_WXSHADOW_SET_BP 0x57580001 /* (pid, addr) 设置隐藏断点 */
#define PR_WXSHADOW_SET_REG 0x57580002 /* (pid, addr, reg, value) 命中时修改寄存器 */
#define PR_WXSHADOW_DEL_BP 0x57580003 /* (pid, addr) 删除断点，addr=0 全部删除 */
#define PR_WXSHADOW_SET_TLB_MODE 0x57580004
#define PR_WXSHADOW_GET_TLB_MODE 0x57580005
#define PR_WXSHADOW_PATCH 0x57580006 /* (pid, addr, buf, len) 自定义 patch 写入影子页 */
#define PR_WXSHADOW_RELEASE 0x57580008 /* (pid, addr) 释放 shadow，addr=0 全部释放 */

/* 返回 0 成功，负值 errno */
static inline int ls_wxshadow_set_bp(pid_t pid, uint64_t addr)
{
    return prctl(PR_WXSHADOW_SET_BP, pid, addr, 0, 0);
}

/* reg_idx: 0-30 = x0-x30，31 = sp */
static inline int ls_wxshadow_set_reg(pid_t pid, uint64_t addr, int reg_idx, uint64_t value)
{
    return prctl(PR_WXSHADOW_SET_REG, pid, addr, reg_idx, value);
}

/* addr = 0 时删除该进程全部断点 */
static inline int ls_wxshadow_del_bp(pid_t pid, uint64_t addr)
{
    return prctl(PR_WXSHADOW_DEL_BP, pid, addr, 0, 0);
}

/* 自定义 patch 写入影子页（不跨页，offset+len <= 4096） */
static inline int ls_wxshadow_patch(pid_t pid, uint64_t addr, const void *data, size_t len)
{
    return prctl(PR_WXSHADOW_PATCH, pid, addr, (unsigned long)data, len);
}

/* addr = 0 时释放该进程全部 shadow */
static inline int ls_wxshadow_release(pid_t pid, uint64_t addr)
{
    return prctl(PR_WXSHADOW_RELEASE, pid, addr, 0, 0);
}

#ifdef __cplusplus
}
#endif

#endif /* LSDRIVER_H */
