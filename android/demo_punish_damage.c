/*
 * demo_punish_damage - 影子页（W^X Shadow Memory）无痕 hook demo
 *
 * 目标：
 *   com.tencent.tmgp.sgame（王者荣耀）
 *   CSkillButtonManager 类 private Int32 <PunishDamage>k__BackingField  // 偏移 0x244
 *   Dll : Scripts.GameCore.dll / Namespace: Assets.Scripts.GameSystem
 *
 * 唯一一种 hook 方式（wxshadow 逻辑），零参数自动运行：
 *   1. 连接 lsdriver 驱动，定位 com.tencent.tmgp.sgame 进程
 *   2. 代码特征搜索：在可执行映射里找 "str wX, [xY, #0x244]" 指令
 *      （ARM64: 0xB9024400 系）——写 PunishDamage 字段的候选指令
 *   3. 对候选指令全部下 wxshadow 影子页无痕断点（BRK 只存在于影子页）
 *   4. 无痕验证：读取候选处指令字节，与下断点前一致（读取路径看不到断点）
 *   5. 命中现场打印到内核日志：dmesg | grep wxshadow
 *      命中 PC = 写字段指令，x0 = CSkillButtonManager 实例指针，
 *      写指令源寄存器 = 本次写入的 PunishDamage 值
 *
 * Ctrl+C 退出并自动删除全部无痕断点。
 *
 * 编译：make -C android CROSS=aarch64-linux-gnu-
 *       （DroidC 等编译器亦可，代码兼容 C/C++ 编译）
 * 运行：./demo_punish_damage     （root，lsdriver 已加载，游戏已进对局）
 */

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

#define MAX_BP_CANDIDATES 64 /* 最多同时对多少个候选下断点 */

/* ========== 全局 ========== */

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* ========== 进程映射解析 ========== */

struct proc_map
{
    uint64_t start;
    uint64_t end;
    char perms[8];
    char path[256];
    bool executable;
};

#define MAX_MAPS 4096

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
        maps[n].executable = strchr(perms, 'x') != NULL;
        snprintf(maps[n].path, sizeof(maps[n].path), "%s", p);
        n++;
    }
    fclose(fp);
    return n;
}

/* ========== 代码特征搜索：写 0x244 字段的指令 ========== */

struct insn_candidate
{
    uint64_t pc;
    uint32_t insn;
    char module[128];
};

/*
 * 在可执行映射中搜索 ARM64 "str wX, [xY, #imm]" 机器码：
 *   STR (unsigned immediate, 32-bit): 0xB9000000 | (imm12<<10) | (Rn<<5) | Rt
 *   imm12 = FIELD_OFFSET >> 2
 * 命中即为"写 PunishDamage 字段"的候选指令。
 */
static int search_write_insns(pid_t pid, struct insn_candidate *cands, int max)
{
    struct proc_map maps[MAX_MAPS];
    int nr = parse_proc_maps(pid, maps, MAX_MAPS);
    if (nr <= 0)
    {
        printf("[error] 解析 /proc/%d/maps 失败\n", pid);
        return 0;
    }

    const uint32_t imm12 = (FIELD_OFFSET >> 2) & 0xFFF;
    uint8_t buf[0x1000];
    int total = 0;

    for (int i = 0; i < nr && total < max; i++)
    {
        if (!maps[i].executable)
            continue; /* 只扫可执行映射 */
        if (!maps[i].path[0])
            continue;
        if (maps[i].end - maps[i].start < 0x10000)
            continue; /* 跳过小映射（vdso 等） */

        for (uint64_t a = maps[i].start; a + 4 <= maps[i].end && total < max; a += 0x1000)
        {
            int got = ls_read(pid, a, buf, sizeof(buf));
            if (got <= 0)
                continue;

            for (int o = 0; o + 4 <= got && total < max; o += 4)
            {
                uint32_t insn;
                memcpy(&insn, buf + o, 4);

                if ((insn & 0xFFC00000) != 0xB9000000)
                    continue; /* 不是 STR 32-bit unsigned immediate */
                if (((insn >> 10) & 0xFFF) != imm12)
                    continue; /* 偏移不是 FIELD_OFFSET */

                cands[total].pc = a + (uint64_t)o;
                cands[total].insn = insn;
                snprintf(cands[total].module, sizeof(cands[total].module), "%s", maps[i].path);
                total++;
            }
        }
    }

    return total;
}

/* ========== 主流程 ========== */

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

    /* 3. 代码特征搜索：写 0x244 字段的指令 */
    printf("\n[search] 搜索 \"str wX, [xY, #0x%x]\" 指令（可执行映射）...\n", FIELD_OFFSET);
    struct insn_candidate cands[MAX_BP_CANDIDATES];
    int nr_cands = search_write_insns(pid, cands, MAX_BP_CANDIDATES);

    if (nr_cands == 0)
    {
        printf("[error] 未找到写 0x%x 的 str 指令（字段可能通过其他指令写入）\n", FIELD_OFFSET);
        return 1;
    }

    printf("[search] 找到 %d 个候选写字段指令:\n", nr_cands);
    for (int i = 0; i < nr_cands; i++)
    {
        unsigned rt = cands[i].insn & 0x1F;
        unsigned rn = (cands[i].insn >> 5) & 0x1F;
        printf("  [%d] 0x%016" PRIx64 "  str w%u, [x%u, #0x%x]  (%s)\n",
               i, cands[i].pc, rt, rn, FIELD_OFFSET, cands[i].module);
    }

    /* 4. 对全部候选下 wxshadow 无痕断点 */
    printf("\n[nohook] 对 %d 个候选下影子页无痕断点...\n", nr_cands);
    int ok = 0;
    for (int i = 0; i < nr_cands; i++)
    {
        if (ls_wxshadow_set_bp(pid, cands[i].pc) == 0)
        {
            ok++;
            printf("  [%d] 断点已设 @ 0x%016" PRIx64 "\n", i, cands[i].pc);
        }
        else
        {
            printf("  [%d] 断点设置失败 @ 0x%016" PRIx64 "（跳过）\n", i, cands[i].pc);
        }
    }
    if (ok == 0)
    {
        printf("[error] 全部断点设置失败\n");
        return 1;
    }

    /* 5. 无痕验证：读取候选处指令字节，与下断点前一致 */
    printf("\n[无痕验证] 读取候选指令（读取路径应看不到断点）:\n");
    for (int i = 0; i < nr_cands; i++)
    {
        uint8_t bytes[4] = {0};
        if (ls_read(pid, cands[i].pc, bytes, sizeof(bytes)) <= 0)
            continue;
        uint32_t cur;
        memcpy(&cur, bytes, 4);
        const char *same = (cur == cands[i].insn) ? "原始指令，无痕 ✓" : "异常!";
        printf("  [%d] 0x%016" PRIx64 ": %02x %02x %02x %02x  %s\n",
               i, cands[i].pc, bytes[0], bytes[1], bytes[2], bytes[3], same);
    }

    /* 6. 命中提示 */
    printf("\n[hook] 无痕断点已生效（wxshadow 逻辑）:\n");
    printf("  游戏写入 PunishDamage 时命中，现场打印到内核日志:\n");
    printf("    dmesg | grep wxshadow\n");
    printf("  命中 PC = 写字段指令地址（对照上方候选列表）\n");
    printf("  x0      = CSkillButtonManager 实例指针\n");
    printf("  源寄存器 = 本次写入的 PunishDamage 值\n");
    printf("  命中时读取该字段的内存也永远看到原始指令（无痕）\n");
    printf("  Ctrl+C 退出并删除全部断点\n");

    while (!g_stop)
        usleep(200 * 1000);

    /* 7. 清理 */
    printf("\n[cleanup] 删除全部无痕断点\n");
    for (int i = 0; i < nr_cands; i++)
        ls_wxshadow_del_bp(pid, cands[i].pc);

    printf("\ndemo 结束\n");
    return 0;
}
