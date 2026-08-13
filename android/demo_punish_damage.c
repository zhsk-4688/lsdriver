/*
 * demo_punish_damage - 通过 lsdriver 驱动 hook 王者荣耀 CSkillButtonManager.PunishDamage 字段
 *
 * 目标：
 *   com.tencent.tmgp.sgame（王者荣耀）
 *   CSkillButtonManager 类 private Int32 <PunishDamage>k__BackingField  // 偏移 0x244
 *   Dll : Scripts.GameCore.dll
 *   Namespace: Assets.Scripts.GameSystem
 *
 * 功能（三种 hook 方式，全部零参数自动运行——自动定位类与实例）：
 *   1. 默认：连接驱动 -> 自动定位 CSkillButtonManager 实例（IL2CPP 元数据
 *      global-metadata.dat + 类名字符串 + 对象头 klass 验证）-> 读取 0x244
 *      字段值并打印
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
 * 运行（root，lsdriver 已加载，游戏已进对局）：
 *   ./demo_punish_damage                          # 自动定位实例并打印字段值
 *   ./demo_punish_damage -w 999                   # 修改字段
 *   ./demo_punish_damage --watch                  # 监控字段被写入（找写入 PC）
 *   ./demo_punish_damage -b 0x6f123456 -r x1=999  # 无痕断点 + 命中改寄存器
 *   ./demo_punish_damage -a 0x7b5c001000          # 手动指定实例地址（覆盖自动定位）
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

/* ========== IL2CPP 自动定位（无需任何参数） ========== */
/*
 * 定位流程：
 *   1. 扫描进程可读映射找 global-metadata.dat 特征（sanity 0xFAB11BAF）
 *   2. 读 metadata 头的 stringOffset/stringCount（偏移 0x18/0x1C，IL2CPP 24~32 稳定）
 *   3. 在字符串池内存中模式匹配类名 "CSkillButtonManager" -> 类名字符串精确地址
 *   4. 扫描进程可写映射：指针 p 指向的对象，其对象头 klass 落在模块映射内，
 *      且 klass 结构附近（±0x200）存在指向类名字符串的指针（Il2CppClass.name）
 *      -> p 就是 CSkillButtonManager 实例
 */

#define MD_SANITY 0xFAB11BAF
#define MD_STRING_OFFSET_FIELD 0x18 /* Il2CppGlobalMetadataHeader.stringOffset */
#define MD_STRING_COUNT_FIELD 0x1C  /* Il2CppGlobalMetadataHeader.stringCount */
#define CLASS_NAME "CSkillButtonManager"
#define CLASS_NS "Assets.Scripts.GameSystem"

#define MAX_MAPS 4096
#define MAX_SCAN_CHUNKS (256UL * 1024 * 1024 / 0x1000) /* 字符串池扫描上限 256MB */

struct proc_map
{
    uint64_t start;
    uint64_t end;
    char perms[8];
    char path[256];
    bool readable;
    bool writable;
};

static int parse_proc_maps(pid_t pid, struct proc_map *maps, int max)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;

    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), fp) && n < max)
    {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        char p[256] = {0};

        if (sscanf(line, "%lx-%lx %7s %*lx %*x:%*x %*lu %255[^\n]",
                   &start, &end, perms, p) < 3)
            continue;
        if (end <= start)
            continue;

        maps[n].start = start;
        maps[n].end = end;
        snprintf(maps[n].perms, sizeof(maps[n].perms), "%s", perms);
        maps[n].readable = strchr(perms, 'r') != NULL;
        maps[n].writable = strchr(perms, 'w') != NULL;
        snprintf(maps[n].path, sizeof(maps[n].path), "%s", p);
        n++;
    }
    fclose(fp);
    return n;
}

/* 1. 扫描 metadata sanity */
static uint64_t locate_metadata(pid_t pid, const struct proc_map *maps, int nr, int *version)
{
    uint8_t buf[0x1000];

    for (int i = 0; i < nr; i++)
    {
        if (!maps[i].readable || maps[i].end - maps[i].start < 8)
            continue;

        int got = ls_read(pid, maps[i].start, buf, sizeof(buf));
        if (got <= 0)
            continue;

        for (int off = 0; off + 8 <= got; off += 4)
        {
            uint32_t sanity;
            memcpy(&sanity, buf + off, 4);
            if (sanity != MD_SANITY)
                continue;

            int32_t ver;
            memcpy(&ver, buf + off + 4, 4);
            if (ver < 24 || ver > 32)
                continue; /* IL2CPP 版本范围（24~32） */

            if (version)
                *version = ver;
            printf("[metadata] 找到 global-metadata.dat: base=0x%016" PRIx64
                   " version=%d\n",
                   maps[i].start + (uint64_t)off, ver);
            return maps[i].start + (uint64_t)off;
        }
    }
    return 0;
}

/* 2+3. 字符串池内模式匹配类名，返回类名字符串地址（可能多个，全部打印，取第一个） */
static uint64_t locate_class_string(pid_t pid, uint64_t metadata_base, uint64_t *out_ns_addr)
{
    uint32_t str_off = 0, str_count = 0;

    if (ls_read(pid, metadata_base + MD_STRING_OFFSET_FIELD, &str_off, 4) <= 0 ||
        ls_read(pid, metadata_base + MD_STRING_COUNT_FIELD, &str_count, 4) <= 0)
        return 0;
    if (str_off == 0 || str_count == 0 || str_count > 0x2000000)
        return 0;

    uint64_t pool = metadata_base + str_off;
    printf("[metadata] 字符串池: base=0x%016" PRIx64 " count=%u\n", pool, str_count);

    static const char pattern[] = CLASS_NAME; /* 含结尾 \0 */
    size_t pat_len = sizeof(pattern) - 1;     /* "CSkillButtonManager" 长度 */

    uint8_t buf[0x1000];
    uint8_t tail[32];
    size_t tail_len = 0;
    uint64_t first = 0;
    int found = 0;

    /* 池大小未知，从 pool 起扫描（上限 256MB） */
    for (uint64_t a = pool; a < pool + MAX_SCAN_CHUNKS * 0x1000; a += 0x1000)
    {
        int got = ls_read(pid, a, buf, sizeof(buf));
        if (got <= 0)
            continue;

        /* 拼接上一块尾部，覆盖跨块模式；逻辑数据从 logical_base 开始 */
        uint8_t combined[0x1000 + 32];
        size_t logical_len = (size_t)got + tail_len;
        uint64_t logical_base = a - tail_len;

        memcpy(combined, tail, tail_len);
        memcpy(combined + tail_len, buf, (size_t)got);

        for (size_t i = 0; i + pat_len <= logical_len; i++)
        {
            if (memcmp(combined + i, pattern, pat_len) != 0)
                continue;

            uint64_t saddr = logical_base + (uint64_t)i;
            printf("[metadata] 类名 \"%s\" @ 0x%016" PRIx64 " (nameIndex=0x%x)\n",
                   CLASS_NAME, saddr, (unsigned)(saddr - pool));
            if (!first)
                first = saddr;
            if (++found >= 10)
            {
                printf("[metadata] 同名过多，停止匹配\n");
                return first;
            }
        }

        /* 保存尾部用于跨块匹配 */
        tail_len = pat_len - 1 < (size_t)got ? pat_len - 1 : (size_t)got;
        memcpy(tail, buf + got - tail_len, tail_len);

        if (found && (a - pool) > 0x100000) /* 找到后最多再确认 1MB */
            break;
    }

    if (found)
        printf("[metadata] 类名字符串匹配 %d 个，采用第一个\n", found);
    return first;
}

/* 模块映射范围（klass 判定用）：按 start 排序，二分查找 */
struct mod_range
{
    uint64_t start;
    uint64_t end;
};

#define MAX_MOD_RANGES 1024

static int collect_module_ranges(const struct proc_map *maps, int nr,
                                 struct mod_range *ranges, int max)
{
    int n = 0;
    for (int i = 0; i < nr && n < max; i++)
    {
        const char *p = maps[i].path;
        if (!p[0])
            continue;
        if (!strstr(p, ".so") && !strstr(p, ".dll") && !strstr(p, ".oat"))
            continue;

        ranges[n].start = maps[i].start;
        ranges[n].end = maps[i].end;
        n++;
    }

    /* 按 start 排序 */
    for (int i = 1; i < n; i++)
    {
        struct mod_range r = ranges[i];
        int j = i - 1;
        while (j >= 0 && ranges[j].start > r.start)
        {
            ranges[j + 1] = ranges[j];
            j--;
        }
        ranges[j + 1] = r;
    }
    return n;
}

static bool addr_in_module_ranges(uint64_t addr, const struct mod_range *ranges, int n)
{
    int lo = 0, hi = n - 1;
    while (lo <= hi)
    {
        int mid = (lo + hi) / 2;
        if (addr < ranges[mid].start)
            hi = mid - 1;
        else if (addr >= ranges[mid].end)
            lo = mid + 1;
        else
            return true;
    }
    return false;
}

/* 4. 扫描实例：p 指向对象，对象头 klass 在模块内，且 klass 附近有类名字符串指针 */
static uint64_t scan_instance(pid_t pid, const struct proc_map *maps, int nr,
                              const struct mod_range *ranges, int nr_ranges,
                              uint64_t class_str_addr, uint64_t *out_klass)
{
    uint8_t chunk[0x1000];
    uint64_t found = 0;
    int candidates = 0;

    printf("\n[scan] 扫描实例（类名验证地址 0x%016" PRIx64 "，模块范围 %d 个）...\n",
           class_str_addr, nr_ranges);

    for (int i = 0; i < nr; i++)
    {
        /* 只扫可写映射（对象/静态字段在可写内存；metadata/只读段跳过） */
        if (!maps[i].writable)
            continue;

        uint64_t start = maps[i].start;
        uint64_t end = maps[i].end;
        uint64_t size = end - start;

        /* 大映射限扫前 32MB */
        if (size > 32UL * 1024 * 1024)
            end = start + 32UL * 1024 * 1024;

        for (uint64_t a = start; a + 8 <= end; a += 0x1000)
        {
            int got = ls_read(pid, a, chunk, sizeof(chunk));
            if (got <= 0)
                continue;

            for (int o = 0; o + 8 <= got; o += 8)
            {
                uint64_t p;
                memcpy(&p, chunk + o, 8);
                if (p < 0x10000 || (p >> 48) != 0)
                    continue; /* 只扫用户态指针 */

                /* 对象头 klass：读 [p]，必须是模块内地址 */
                uint64_t klass = 0;
                if (ls_read(pid, p, &klass, 8) <= 0)
                    continue;
                if (!addr_in_module_ranges(klass, ranges, nr_ranges))
                    continue;

                /* 验证：klass 结构（Il2CppClass）附近存在指向类名字符串的指针 */
                uint8_t kbuf[0x1000];
                uint64_t kpage = klass & ~0xFFFULL;
                if (ls_read(pid, kpage, kbuf, sizeof(kbuf)) <= 0)
                    continue;

                bool match = false;
                for (int ko = 0; ko + 8 <= (int)sizeof(kbuf); ko += 8)
                {
                    uint64_t v;
                    memcpy(&v, kbuf + ko, 8);
                    if (v == class_str_addr)
                    {
                        match = true;
                        break;
                    }
                }
                if (!match)
                    continue;

                uint64_t obj = p;
                printf("[candidate] 实例=0x%016" PRIx64 "  klass=0x%016" PRIx64
                       "  引用槽位=0x%016" PRIx64 "\n",
                       obj, klass, a + (uint64_t)o);
                candidates++;
                if (!found)
                {
                    found = obj;
                    if (out_klass)
                        *out_klass = klass;
                }
                if (candidates >= 10)
                {
                    printf("[scan] 候选过多，停止扫描\n");
                    return found;
                }
            }

            if (g_stop)
                return found;
        }
    }

    printf("[scan] 扫描完成，候选 %d 个\n", candidates);
    return found;
}

/*
 * 自动定位 CSkillButtonManager 实例（零参数）。
 * 返回实例地址；失败返回 0。
 */
static uint64_t auto_locate_instance(pid_t pid)
{
    struct proc_map maps[MAX_MAPS];
    int nr = parse_proc_maps(pid, maps, MAX_MAPS);
    if (nr <= 0)
    {
        printf("[error] 解析 /proc/%d/maps 失败\n", pid);
        return 0;
    }

    /* 1. metadata */
    int md_version = 0;
    uint64_t md = locate_metadata(pid, maps, nr, &md_version);
    if (!md)
    {
        printf("[error] 未找到 global-metadata.dat（sanity 0x%x），请用 -a 指定实例地址\n",
               MD_SANITY);
        return 0;
    }

    /* 2. 类名字符串 */
    uint64_t class_str = locate_class_string(pid, md, NULL);
    if (!class_str)
    {
        printf("[error] 字符串池中未找到类名 \"%s\"\n", CLASS_NAME);
        return 0;
    }

    /* 3. 模块范围 + 实例扫描 */
    struct mod_range ranges[MAX_MOD_RANGES];
    int nr_ranges = collect_module_ranges(maps, nr, ranges, MAX_MOD_RANGES);
    if (nr_ranges <= 0)
    {
        printf("[error] 未找到任何模块映射\n");
        return 0;
    }

    return scan_instance(pid, maps, nr, ranges, nr_ranges, class_str, NULL);
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

    /* 4. 定位实例：-a 指定，否则 IL2CPP 元数据自动定位（零参数） */
    if (!instance)
    {
        instance = auto_locate_instance(pid);
        if (!instance)
        {
            printf("[error] 自动定位失败，请用 -a <addr> 直接指定实例地址\n");
            free(mem);
            return 1;
        }
        printf("[scan] 采用实例: 0x%016" PRIx64 "\n", instance);
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
