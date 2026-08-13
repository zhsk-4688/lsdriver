
#ifndef IO_STRUCT_H
#define IO_STRUCT_H
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/pgtable.h>
#include <asm/pgtable-prot.h>
#include <asm/memory.h>
#include <asm/barrier.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/sort.h>
#include <linux/types.h>

#define MAX_MODULES      1024
#define MAX_SCAN_REGIONS 16534

#define MOD_NAME_LEN        256
#define MAX_SEGS_PER_MODULE 512

struct segment_info
{
    short index;  // >=0: 普通段(RX→RO→RW连续编号), -1: BSS段
    uint8_t prot; // 区段权限: 1(R), 2(W), 4(X)。例如 RX 就是 5 (1+4)
    uint64_t start;
    uint64_t end;
};

struct module_info
{
    char name[MOD_NAME_LEN];
    int seg_count;
    struct segment_info segs[MAX_SEGS_PER_MODULE];
};

struct region_info
{
    uint64_t start;
    uint64_t end;
};

struct virtual_memory
{
    int module_count;                        // 总模块数量
    struct module_info modules[MAX_MODULES]; // 模块信息

    int region_count;                             // 总可扫描内存数量
    struct region_info regions[MAX_SCAN_REGIONS]; // 可扫描内存区域 (rw-p, 排除特殊区域)
};

struct virtual_memoryrw
{
    uint64_t rw_addr;            // 读写的地址
    uint8_t user_buffer[0x1000]; // 物理标准页大小的数据缓存区
    int size;                    // 读写的大小
};

enum request_op
{
    request_op_none,       // 空调用
    request_op_vmem_read,  // 读取内存
    request_op_vmem_write, // 写入内存
    request_op_vmem_info,  // 获取进程内存信息

    request_op_kernel_exit, // 内核线程退出

};

// 将在队列中使用的请求实例结构体
struct request_obj
{
    /*
    两者都不保证 ARM64 多核间的硬件内存顺序
    volatile 约束对象的每次访问，防止编译器省略、合并或用寄存器缓存该字段
    但不会绕过 CPU Cache。对应到硬件屏障就是
    dsb:数据访问屏障,等读写内存完成 
    isb:指令执行屏障,CPU流水线重新取址
    
    asm volatile("" ::: "memory") 是当前位置的编译器内存屏障，禁止其它内存访问跨越它重排，是编译时防止指令重排
    但不会绕过硬件指令访问乱序
    dmb:指令访问顺序屏障,load/store 内存访问指令的约束乱序访问
   
    然后dsb,isb,dmb指令操作数都是共享域范围:ish / nsh / osh / ishst
    */
    volatile bool kernel;        // 由用户模式设置 true = 内核有待处理的请求, false = 请求已完成
    volatile bool user;          // 由内核模式设置 true = 用户模式有待处理的请求, false = 请求已完成
    volatile enum request_op op; // 请求操作类型
    volatile int status;         // 请求操作状态

    int tgid; // 当前派发指定的进程 TGID

    // 虚拟内存读写信息
    struct virtual_memoryrw vmemrw_info;
    // 虚拟内存信息
    struct virtual_memory vmem_info;
};

#endif // IO_STRUCT_H
