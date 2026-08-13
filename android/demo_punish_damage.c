/*
 * demo_punish_damage - 影子页（W^X Shadow Memory）无痕 hook demo
 *
 * 目标：
 *   com.tencent.tmgp.sgame（王者荣耀）
 *   CSkillButtonManager 类 private Int32 <PunishDamage>k__BackingField  // 偏移 0x244
 *   Dll : Scripts.GameCore.dll / Namespace: Assets.Scripts.GameSystem
 *
 * 全自动、零参数（int main(void)）：
 *   1. 连接 lsdriver 驱动，定位 com.tencent.tmgp.sgame 进程
 *   2. IL2CPP 元数据自动定位 CSkillButtonManager 实例
 *      （global-metadata.dat sanity 扫描 -> 字符串池匹配类名 ->
 *       对象头 klass + 类名字符串指针双重验证）
 *   3. 硬件写观察点捕获"写字段的指令地址" PC（一次命中即取到）
 *   4. 移除观察点，在 PC 处下 wxshadow 无痕断点（影子页写 BRK）
 *   5. 无痕验证：下断点前后读取 PC 处指令字节，应完全一致
 *      （读取路径永远看到原始指令，BRK 只存在于影子页）
 *   6. 轮询打印 PunishDamage 字段值变化；命中现场/寄存器见内核日志：
 *      dmesg | grep wxshadow
 *
 * Ctrl+C 退出并自动删除无痕断点。
 *
 * 编译：make -C android CROSS=aarch64-linux-gnu-
 * 运行：./demo_punish_damage     （root，lsdriver 已加载，游戏已进对局）
 */

#define _GNU_SOURCE

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

#define TARGET_PACKAGE "com.tencent.tmgp.sgame"
#define CLASS_NAME     "CSkillButtonManager"
#define FIELD_OFFSET   0x244 /* <PunishDamage>k__BackingField, int32 */

/* ========== 全局 ========== */

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* ========== IL2CPP 自动定位（零参数） ========== */

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

/* 2+3. 字符串池内模式匹配类名，返回类名字符串地址（可能多个，取第一个） */
static uint64_t locate_class_string(pid_t pid, uint64_t metadata_base)
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
    size_t pat_len = sizeof(pattern) - 1;

    uint8_t buf[0x1000];
    uint8_t tail[32];
    size_t tail_len = 0;
    uint64_t first = 0;
    int found = 0;

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
                              uint64_t class_str_addr)
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

                printf("[candidate] 实例=0x%016" PRIx64 "  klass=0x%016" PRIx64
                       "  引用槽位=0x%016" PRIx64 "\n",
                       p, klass, a + (uint64_t)o);
                candidates++;
                if (!found)
                    found = p;
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

/* 自动定位 CSkillButtonManager 实例（零参数）。返回实例地址；失败返回 0。 */
static uint64_t auto_locate_instance(pid_t pid)
{
    struct proc_map maps[MAX_MAPS];
    int nr = parse_proc_maps(pid, maps, MAX_MAPS);
    if (nr <= 0)
    {
        printf("[error] 解析 /proc/%d/maps 失败\n", pid);
        return 0;
    }

    int md_version = 0;
    uint64_t md = locate_metadata(pid, maps, nr, &md_version);
    if (!md)
    {
        printf("[error] 未找到 global-metadata.dat（sanity 0x%x）\n", MD_SANITY);
        return 0;
    }

    uint64_t class_str = locate_class_string(pid, md);
    if (!class_str)
    {
        printf("[error] 字符串池中未找到类名 \"%s\"\n", CLASS_NAME);
        return 0;
    }

    struct mod_range ranges[MAX_MOD_RANGES];
    int nr_ranges = collect_module_ranges(maps, nr, ranges, MAX_MOD_RANGES);
    if (nr_ranges <= 0)
    {
        printf("[error] 未找到任何模块映射\n");
        return 0;
    }

    return scan_instance(pid, maps, nr, ranges, nr_ranges, class_str);
}

/* ========== 字段读取 ========== */

static int32_t read_field(pid_t pid, uint64_t instance)
{
    int32_t v = 0;
    if (ls_read(pid, instance + FIELD_OFFSET, &v, sizeof(v)) <= 0)
        return 0;
    return v;
}

/* ========== 影子页无痕 hook 主流程 ========== */

/*
 * 第一步：硬件写观察点捕获"写字段的指令地址" PC。
 * 命中记录由驱动直接写入共享内存（req->bp_info），轮询即可。
 * 返回写指令 PC；超时返回 0。
 */
static uint64_t capture_write_pc(pid_t pid, uint64_t instance)
{
    struct ls_break_point bp;
    uint64_t watch_addr = instance + FIELD_OFFSET;
    uint64_t pc = 0;

    printf("\n[step 1/4] 硬件写观察点 @ 0x%016" PRIx64 "（捕获写字段指令，最多等 60 秒）...\n",
           watch_addr);

    if (ls_hwbp_set(pid, watch_addr, BP_BREAKPOINT_W, BP_BREAKPOINT_LEN_4, &bp) < 0)
    {
        printf("[error] 设置观察点失败\n");
        return 0;
    }

    for (int i = 0; i < 300 && !g_stop; i++)
    {
        struct ls_bp_point *pt = &g_req->bp_info.points[0];
        if (pt->record_count > 0 && pt->records[0].hit_count > 0)
        {
            pc = pt->records[0].pc;
            break;
        }
        usleep(200 * 1000);
    }

    ls_hwbp_remove();
    if (!pc)
    {
        printf("[error] 超时未捕获写字段（游戏需进对局并触发过该字段写入）\n");
        return 0;
    }

    printf("[step 1/4] 写字段指令 PC = 0x%016" PRIx64 "\n", pc);
    return pc;
}

/*
 * 主流程：在写字段指令处下影子页无痕断点，无痕验证 + 轮询打印字段值。
 */
static void run_nohook(pid_t pid, uint64_t instance)
{
    uint64_t pc = capture_write_pc(pid, instance);
    if (!pc)
        return;

    /* 无痕验证：下断点前后读取同一代码地址的指令字节 */
    uint8_t insn_before[4] = {0}, insn_after[4] = {0};
    ls_read(pid, pc, insn_before, sizeof(insn_before));

    printf("\n[step 2/4] 下 wxshadow 影子页无痕断点 @ 0x%016" PRIx64 " ...\n", pc);
    if (ls_wxshadow_set_bp(pid, pc) < 0)
    {
        printf("[error] 无痕断点设置失败\n");
        return;
    }

    ls_read(pid, pc, insn_after, sizeof(insn_after));

    printf("\n[无痕验证] 断点地址指令字节（读取视角，前后应完全一致）:\n");
    printf("  下断点前: %02x %02x %02x %02x\n",
           insn_before[0], insn_before[1], insn_before[2], insn_before[3]);
    printf("  下断点后: %02x %02x %02x %02x\n",
           insn_after[0], insn_after[1], insn_after[2], insn_after[3]);
    if (memcmp(insn_before, insn_after, sizeof(insn_before)) == 0)
        printf("  => 一致！BRK 只存在于影子页，读取路径看不到断点，无痕生效\n");
    else
        printf("  => 不一致，请检查驱动日志\n");

    printf("\n[step 3/4] 断点已生效。命中现场见内核日志: dmesg | grep wxshadow\n");
    printf("[step 4/4] 轮询 PunishDamage 字段值变化（Ctrl+C 退出并删除断点）\n");

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

    printf("\n[cleanup] 删除无痕断点\n");
    ls_wxshadow_del_bp(pid, pc);
}

/* ========== main（零参数） ========== */

int main(void)
{
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    printf("===== 影子页无痕 hook demo：CSkillButtonManager.PunishDamage (0x%x) =====\n",
           FIELD_OFFSET);

    /* 1. 连接驱动 */
    printf("[lsdriver] 连接驱动...\n");
    int ret = ls_connect();
    if (ret < 0)
    {
        printf("[error] 连接失败: %d（驱动是否已 insmod？是否 root？）\n", ret);
        return 1;
    }
    printf("[lsdriver] 已连接\n");

    /* 2. 定位进程 */
    pid_t pid = ls_find_pid_by_name(TARGET_PACKAGE);
    if (pid <= 0)
    {
        printf("[error] 找不到进程 %s（游戏是否在运行？）\n", TARGET_PACKAGE);
        return 1;
    }
    printf("[target] pid = %d (%s)\n", pid, TARGET_PACKAGE);

    /* 3. IL2CPP 自动定位实例 */
    printf("\n[定位] CSkillButtonManager 实例（IL2CPP 元数据）...\n");
    uint64_t instance = auto_locate_instance(pid);
    if (!instance)
    {
        printf("[error] 自动定位失败（游戏需已进对局）\n");
        return 1;
    }
    printf("[定位] 实例 = 0x%016" PRIx64 "\n", instance);

    /* 4. 影子页无痕 hook */
    run_nohook(pid, instance);

    printf("\ndemo 结束\n");
    return 0;
}
