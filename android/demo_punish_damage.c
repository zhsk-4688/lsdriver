/*
 * demo_punish_damage - 通过 lsdriver 驱动 hook 王者荣耀 CSkillButtonManager.PunishDamage 字段
 *
 * 目标：
 *   com.tencent.tmgp.sgame（王者荣耀）
 *   CSkillButtonManager 类 private Int32 <PunishDamage>k__BackingField  // 偏移 0x244
 *   Dll : Scripts.GameCore.dll
 *   Namespace: Assets.Scripts.GameSystem
 *
 * 功能（三种 hook 方式）：
 *   1. 默认：连接驱动，定位实例后读取 0x244 字段值并打印（普通内存读取）
 *   2. -b <代码地址>：wxshadow 无痕隐藏断点（W^X 影子页）
 *      在写/读 PunishDamage 字段的指令地址下断点：进程读取该页永远看到
 *      原始指令（无痕），执行到断点地址触发 BRK；命中现场打印到内核日志
 *      （dmesg | grep wxshadow）；-r 可修改命中时的寄存器（hook 改字段值）；
 *      demo 同时轮询字段值变化打印
 *   3. --watch：arm64 硬件写观察点（WRP），监控字段被游戏写入，打印命中 PC
 *      与寄存器现场（可用来先找出"写字段的指令地址"，再配合 -b 转成无痕断点）
 *
 * 编译：
 *   aarch64-linux-gnu-gcc -O2 -static -o demo_punish_damage demo_punish_damage.c
 *
 * 运行（root，lsdriver 已加载）：
 *   ./demo_punish_damage                          # 自动扫描实例并打印字段值
 *   ./demo_punish_damage -a 0x7b5c001000          # 直接指定实例地址
 *   ./demo_punish_damage -a 0x7b5c001000 -w 999   # 修改字段
 *   ./demo_punish_damage -a 0x7b5c001000 --watch  # 监控字段被写入（找写入 PC）
 *   ./demo_punish_damage -a 0x7b5c001000 \
 *       -b 0x6f123456 -r x1=999                   # 无痕断点 + 命中改寄存器
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lsdriver.h"

/* ========== 目标定义 ========== */

#define TARGET_PACKAGE   "com.tencent.tmgp.sgame"
#define FIELD_NAME       "<PunishDamage>k__BackingField"
#define FIELD_OFFSET     0x244 /* int32 */

/* 候选代码模块关键字（IL2CPP 游戏代码所在模块） */
static const char *const k_code_module_keywords[] = {
    "GameCore",
    "il2cpp",
};

/* 扫描候选的伤害值合理范围 */
#define PUNISH_VALUE_MIN 0
#define PUNISH_VALUE_MAX 100000

/* ========== 全局 ========== */

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static bool str_contains_any(const char *s, const char *const *keys, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (s && keys[i] && strcasestr(s, keys[i]))
            return true;
    }
    return false;
}

/* ========== 模块与代码段收集 ========== */

struct code_seg
{
    uint64_t start;
    uint64_t end;
};

#define MAX_CODE_SEGS 64

static int collect_code_segments(struct ls_virtual_memory *mem, struct code_seg *segs, int max_segs)
{
    int n = 0;

    for (int i = 0; i < mem->module_count && n < max_segs; i++)
    {
        const struct ls_module_info *mod = &mem->modules[i];

        if (!str_contains_any(mod->name, k_code_module_keywords, 2))
            continue;

        printf("[module] %-48s base=0x%016" PRIx64 "\n", mod->name,
               mod->seg_count ? mod->segs[0].start : 0);

        for (int s = 0; s < mod->seg_count && n < max_segs; s++)
        {
            const struct ls_segment_info *seg = &mod->segs[s];
            if ((seg->prot & 4) && seg->start < seg->end) /* 可执行段 */
            {
                segs[n].start = seg->start;
                segs[n].end = seg->end;
                n++;
            }
        }
    }
    return n;
}

static bool addr_in_code_segs(uint64_t addr, const struct code_seg *segs, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (addr >= segs[i].start && addr < segs[i].end)
            return true;
    }
    return false;
}

/* ========== 实例定位 ========== */

/*
 * 指针扫描：在 rw 扫描区里找"对象头 klass 指向 GameCore/il2cpp 代码段"的指针，
 * 并验证 [p + 0x244] 读出合理 int32。命中打印候选。
 * 返回第一个候选地址，没有返回 0。
 */
static uint64_t scan_for_instance(pid_t pid, struct ls_virtual_memory *mem,
                                  const struct code_seg *segs, int nr_segs)
{
    uint64_t found = 0;
    int candidates = 0;

    printf("\n[scan] 扫描实例中（代码段 %d 个，扫描区 %d 个）...\n", nr_segs, mem->region_count);

    for (int r = 0; r < mem->region_count; r++)
    {
        uint64_t start = mem->regions[r].start;
        uint64_t end = mem->regions[r].end;
        uint64_t region_size = end - start;

        /* 大区域限扫前 16MB，避免扫描时间过长 */
        if (region_size > 16UL * 1024 * 1024)
            end = start + 16UL * 1024 * 1024;

        for (uint64_t a = start; a + 8 <= end; a += 0x1000)
        {
            uint64_t chunk[0x1000 / 8];
            int got = ls_read(pid, a, chunk, sizeof(chunk));
            if (got <= 0)
                continue;

            for (size_t i = 0; i < sizeof(chunk) / 8; i++)
            {
                uint64_t p = chunk[i];
                if (p < 0x1000 || (p >> 48) != 0)
                    continue; /* 只扫用户态指针 */

                /* 对象头 klass 指向代码段 */
                if (!addr_in_code_segs(p, segs, nr_segs))
                    continue;

                /* 验证字段值 */
                int32_t v = 0;
                if (ls_read(pid, p + FIELD_OFFSET, &v, sizeof(v)) <= 0)
                    continue;

                if (v >= PUNISH_VALUE_MIN && v <= PUNISH_VALUE_MAX)
                {
                    uint64_t obj_addr = a + i * 8;
                    printf("[candidate] obj=0x%016" PRIx64 "  klass=0x%016" PRIx64
                           "  punish=%d (0x%x)\n",
                           obj_addr, p, v, (unsigned)v);
                    candidates++;
                    if (!found)
                        found = obj_addr;
                    if (candidates >= 20)
                    {
                        printf("[scan] 候选过多，停止扫描\n");
                        return found;
                    }
                }
            }

            if (g_stop)
                return found;
        }
    }

    printf("[scan] 扫描完成，候选 %d 个\n", candidates);
    return found;
}

/* ========== 字段读写 ========== */

static int32_t read_field(pid_t pid, uint64_t instance)
{
    int32_t v = 0;
    if (ls_read(pid, instance + FIELD_OFFSET, &v, sizeof(v)) <= 0)
    {
        printf("[error] 读取字段失败\n");
        return 0;
    }
    return v;
}

static void print_field(pid_t pid, uint64_t instance)
{
    int32_t v = read_field(pid, instance);
    printf("\n===== %s.%s =====\n", "CSkillButtonManager", FIELD_NAME);
    printf("instance        = 0x%016" PRIx64 "\n", instance);
    printf("field offset    = 0x%x\n", FIELD_OFFSET);
    printf("field address   = 0x%016" PRIx64 "\n", instance + FIELD_OFFSET);
    printf("PunishDamage    = %d (0x%x)\n", v, (unsigned)v);
    printf("===========================\n");
}

/* ========== wxshadow 无痕断点 ========== */

#define MAX_REG_MODS 4

struct reg_mod
{
    int reg_idx; /* 0-30 = x0-x30, 31 = sp */
    uint64_t value;
};

/* 解析 "x1=999" 或 "sp=0x100" */
static int parse_reg_mod(const char *str, struct reg_mod *mod)
{
    const char *eq = strchr(str, '=');
    if (!eq || eq == str)
        return -1;

    char name[16];
    size_t len = (size_t)(eq - str);
    if (len >= sizeof(name))
        return -1;
    memcpy(name, str, len);
    name[len] = '\0';

    if (strcasecmp(name, "sp") == 0)
        mod->reg_idx = 31;
    else if (tolower(name[0]) == 'x' && name[1] >= '0' && name[1] <= '9')
    {
        int idx = atoi(name + 1);
        if (idx < 0 || idx > 30)
            return -1;
        mod->reg_idx = idx;
    }
    else
        return -1;

    mod->value = strtoull(eq + 1, NULL, 0);
    return 0;
}

/*
 * 无痕断点模式：
 *   1. 下断点前读代码地址指令字节
 *   2. PR_WXSHADOW_SET_BP 在代码地址下隐藏断点（影子页写 BRK）
 *   3. 可选 PR_WXSHADOW_SET_REG 配置命中时寄存器修改
 *   4. 下断点后再读同一地址指令字节 —— 与下断点前完全一致，
 *      证明读取路径永远看到原始指令（无痕）
 *   5. 轮询字段值变化并打印（命中现场/寄存器见 dmesg | grep wxshadow）
 */
static void nohook_field(pid_t pid, uint64_t instance, uint64_t code_addr,
                         const struct reg_mod *mods, int nr_mods)
{
    uint8_t insn_before[4] = {0}, insn_after[4] = {0};

    printf("\n[nohook] 下断点前读取代码地址 0x%016" PRIx64 " ...\n", code_addr);
    if (ls_read(pid, code_addr, insn_before, sizeof(insn_before)) <= 0)
        printf("[warn] 读取断点地址失败\n");

    printf("[nohook] 设置 wxshadow 无痕隐藏断点 @ 0x%016" PRIx64 " ...\n", code_addr);
    int ret = ls_wxshadow_set_bp(pid, code_addr);
    if (ret < 0)
    {
        printf("[error] 设置无痕断点失败: %d\n", ret);
        return;
    }
    printf("[nohook] 断点已设置（执行时触发，读取时无痕）\n");

    for (int i = 0; i < nr_mods; i++)
    {
        ret = ls_wxshadow_set_reg(pid, code_addr, mods[i].reg_idx, mods[i].value);
        if (ret < 0)
            printf("[error] 设置寄存器修改 x%d 失败: %d\n", mods[i].reg_idx, ret);
        else
            printf("[nohook] 命中时修改 x%-2d = 0x%llx\n",
                   mods[i].reg_idx, (unsigned long long)mods[i].value);
    }

    /* 无痕性演示：断点已设置，但读到的仍应是原始指令 */
    if (ls_read(pid, code_addr, insn_after, sizeof(insn_after)) <= 0)
        printf("[warn] 再次读取断点地址失败\n");

    printf("\n[无痕演示] 断点地址指令字节（读取视角，下断点前后应完全一致）:\n");
    printf("  下断点前: %02x %02x %02x %02x\n",
           insn_before[0], insn_before[1], insn_before[2], insn_before[3]);
    printf("  下断点后: %02x %02x %02x %02x\n",
           insn_after[0], insn_after[1], insn_after[2], insn_after[3]);
    if (memcmp(insn_before, insn_after, sizeof(insn_before)) == 0)
        printf("  => 一致！读取路径看不到断点（BRK 只存在于影子页），无痕生效\n");
    else
        printf("  => 不一致，请检查驱动日志\n");

    printf("\n[nohook] 轮询字段值变化（Ctrl+C 退出；命中现场见 dmesg | grep wxshadow）\n");
    int32_t last = read_field(pid, instance);
    printf("  PunishDamage = %d\n", last);

    while (!g_stop)
    {
        int32_t v = read_field(pid, instance);
        if (v != last)
        {
            printf("  [changed] PunishDamage %d -> %d\n", last, v);
            last = v;
        }
        usleep(100 * 1000);
    }

    printf("\n[nohook] 清理：删除断点\n");
    ls_wxshadow_del_bp(pid, code_addr);
}

/* ========== 硬件写观察点监控 ========== */

static void watch_field(pid_t pid, uint64_t instance)
{
    struct ls_break_point bp;
    uint64_t watch_addr = instance + FIELD_OFFSET;

    printf("\n[watch] 对 0x%016" PRIx64 " 设置硬件写观察点（Ctrl+C 退出）...\n", watch_addr);

    int ret = ls_hwbp_set(pid, watch_addr, BP_BREAKPOINT_W, BP_BREAKPOINT_LEN_4, &bp);
    if (ret < 0)
    {
        printf("[error] 设置观察点失败: %d（驱动是否已编译 arm64_hwdbg？）\n", ret);
        return;
    }

    uint64_t last_hits[BP_RECORD_MAX] = {0};
    int printed = 0;

    while (!g_stop)
    {
        /* 驱动把命中记录直接写入共享内存的 req->bp_info，直接读取 */
        struct ls_bp_point *pt = &g_req->bp_info.points[0];

        for (int i = 0; i < pt->record_count && i < BP_RECORD_MAX; i++)
        {
            const struct ls_bp_record *rec = &pt->records[i];
            if (rec->hit_count > last_hits[i])
            {
                uint64_t delta = rec->hit_count - last_hits[i];
                printf("\n[hit #%llu] PC=0x%016llx  LR=0x%016llx\n",
                       (unsigned long long)rec->hit_count,
                       (unsigned long long)rec->pc,
                       (unsigned long long)rec->lr);
                printf("  x0=%016llx x1=%016llx x2=%016llx x3=%016llx\n",
                       (unsigned long long)rec->x0, (unsigned long long)rec->x1,
                       (unsigned long long)rec->x2, (unsigned long long)rec->x3);
                printf("  x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",
                       (unsigned long long)rec->x4, (unsigned long long)rec->x5,
                       (unsigned long long)rec->x6, (unsigned long long)rec->x7);
                printf("  [%u 次] PunishDamage = %d\n", (unsigned)delta,
                       read_field(pid, instance));
                last_hits[i] = rec->hit_count;
                printed++;
            }
        }
        usleep(100 * 1000);
    }

    ls_hwbp_remove();
    printf("\n[watch] 退出，共打印 %d 次命中\n", printed);
}

/* ========== main ========== */

static void usage(const char *prog)
{
    printf("usage: %s [options]\n", prog);
    printf("  -p <pid|包名>   目标进程（默认 %s）\n", TARGET_PACKAGE);
    printf("  -a <addr>       直接指定 CSkillButtonManager 实例地址（跳过扫描）\n");
    printf("  -w <value>      修改 PunishDamage 字段值后重新读取打印\n");
    printf("  -b <addr>       wxshadow 无痕隐藏断点：在读写字段的代码地址下断点\n");
    printf("                  （先用 --watch 观察命中 PC，或在反编译工具里找写 0x244 的指令）\n");
    printf("  -r xN=<value>   无痕断点命中时修改寄存器（如 -r x1=999，可多次）\n");
    printf("  --watch         硬件写观察点，监控字段被写入并打印命中 PC/寄存器\n");
    printf("  -m              只打印模块列表\n");
    printf("  -h              帮助\n");
}

int main(int argc, char *argv[])
{
    static const struct option long_opts[] = {
        {"pid", required_argument, 0, 'p'},
        {"addr", required_argument, 0, 'a'},
        {"write", required_argument, 0, 'w'},
        {"bp", required_argument, 0, 'b'},
        {"reg", required_argument, 0, 'r'},
        {"watch", no_argument, 0, 'W'},
        {"modules", no_argument, 0, 'm'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

    const char *target = TARGET_PACKAGE;
    uint64_t instance = 0;
    uint64_t bp_addr = 0;
    int32_t write_val = 0;
    bool do_write = false;
    bool do_watch = false;
    bool only_modules = false;
    struct reg_mod reg_mods[MAX_REG_MODS];
    int nr_reg_mods = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "p:a:w:b:r:Wmh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'p':
            target = optarg;
            break;
        case 'a':
            instance = strtoull(optarg, NULL, 0);
            break;
        case 'w':
            write_val = (int32_t)strtol(optarg, NULL, 0);
            do_write = true;
            break;
        case 'b':
            bp_addr = strtoull(optarg, NULL, 0);
            break;
        case 'r':
            if (nr_reg_mods >= MAX_REG_MODS)
            {
                fprintf(stderr, "寄存器修改最多 %d 个\n", MAX_REG_MODS);
                return 1;
            }
            if (parse_reg_mod(optarg, &reg_mods[nr_reg_mods]) < 0)
            {
                fprintf(stderr, "非法寄存器修改: %s（格式 xN=value 或 sp=value）\n", optarg);
                return 1;
            }
            nr_reg_mods++;
            break;
        case 'W':
            do_watch = true;
            break;
        case 'm':
            only_modules = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* 1. 连接驱动 */
    printf("[lsdriver] 连接驱动...\n");
    int ret = ls_connect();
    if (ret < 0)
    {
        printf("[error] 连接失败: %d（驱动是否已 insmod？是否 root？）\n", ret);
        return 1;
    }
    printf("[lsdriver] 已连接\n");

    /* 2. 定位目标进程 */
    pid_t pid = -1;
    if (target[0] >= '0' && target[0] <= '9')
        pid = (pid_t)atoi(target);
    else
        pid = ls_find_pid_by_name(target);
    if (pid <= 0)
    {
        printf("[error] 找不到进程: %s（游戏是否在运行？）\n", target);
        return 1;
    }
    printf("[target] pid = %d (%s)\n", pid, target);

    /* 3. 枚举内存布局 */
    struct ls_virtual_memory *mem = malloc(sizeof(*mem));
    if (!mem)
        return 1;
    ret = ls_get_memory_info(pid, mem);
    if (ret < 0)
    {
        printf("[error] 枚举内存失败: %d\n", ret);
        free(mem);
        return 1;
    }
    printf("[target] modules=%d regions=%d\n", mem->module_count, mem->region_count);

    struct code_seg segs[MAX_CODE_SEGS];
    int nr_segs = collect_code_segments(mem, segs, MAX_CODE_SEGS);

    if (only_modules)
    {
        free(mem);
        return 0;
    }

    /* 4. 定位实例 */
    if (!instance)
    {
        instance = scan_for_instance(pid, mem, segs, nr_segs);
        if (!instance)
        {
            printf("[error] 未找到实例，请用 -a <addr> 直接指定（可用 --watch 前的候选打印或反编译工具定位）\n");
            free(mem);
            return 1;
        }
        printf("[scan] 采用候选: 0x%016" PRIx64 "\n", instance);
    }

    /* 5. 修改字段（可选） */
    if (do_write)
    {
        if (ls_write(pid, instance + FIELD_OFFSET, &write_val, sizeof(write_val)) <= 0)
            printf("[error] 写入字段失败\n");
        else
            printf("[write] 已写入 PunishDamage = %d\n", write_val);
    }

    /* 6. wxshadow 无痕断点模式（可选） */
    if (bp_addr)
    {
        nohook_field(pid, instance, bp_addr, reg_mods, nr_reg_mods);
        free(mem);
        return 0;
    }

    /* 7. 打印字段值 */
    print_field(pid, instance);

    /* 8. 观察点监控（可选） */
    if (do_watch)
        watch_field(pid, instance);

    free(mem);
    return 0;
}
