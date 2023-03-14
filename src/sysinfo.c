#include <stdint.h>

#include <windows.h>
#include <sysinfoapi.h>

#include <libjj/utils.h>
#include <libjj/logging.h>
#include <libjj/ffs.h>

#include "sysinfo.h"

typedef struct _PROCESSOR_RELATIONSHIP_WIN11 {
        BYTE Flags;
        BYTE EfficiencyClass;
        BYTE Reserved[20];
        WORD GroupCount;
        GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
} PROCESSOR_RELATIONSHIP_WIN11, *PPROCESSOR_RELATIONSHIP_WIN11;


sys_info_t g_sys_info = { 0 };

int cpu_topology_info_process(sys_info_t *sysinfo, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX pslpi)
{
        union {
                PPROCESSOR_RELATIONSHIP_WIN11 Processor;
                PNUMA_NODE_RELATIONSHIP NumaNode;
                PCACHE_RELATIONSHIP Cache;
                PGROUP_RELATIONSHIP Group;
        } u;

        static int32_t curr_grp = 0;

        size_t grp_nr_cpu = find_first_zero_bit_u64(&sysinfo->cpu_grp[curr_grp].grp_mask) - 1;

        u.Processor = (void *)&pslpi->Processor;

        switch (pslpi->Relationship) {
        case RelationProcessorPackage: {
                // FIXME: behavior changed on Windows 11 ?
//                WORD GroupCount = u.Processor->GroupCount;
//                PGROUP_AFFINITY GroupMask = u.Processor->GroupMask;

//                if (GroupCount > 1) {
//                        pr_err("unexpected: GroupCount %hu > 1\n", GroupCount);
//                        return -EINVAL;
//                }

//                do {
//                        pr_info("group<%u> Mask = %016llx\n", GroupMask->Group, GroupMask->Mask);
//                } while (GroupMask++, --GroupCount);

//                sysinfo->cpu_grp[curr_grp++].grp_mask = GroupMask->Mask;
                break;
        }

        case RelationProcessorCore: {
                uint64_t relation_mask = u.Processor->GroupMask->Mask;
                uint64_t t = relation_mask;
                size_t curr_cpu;

                do {
                        struct cpu_mask *m;

                        curr_cpu = find_first_bit_u64(&t);

                        // if relation_mask is all ZERO
                        if (curr_cpu == 64)
                                break;

                        m = &(sysinfo->cpu_grp[curr_grp].cpu_mask[curr_cpu]);
                        m->relation_mask = relation_mask;

                        if (u.Processor->EfficiencyClass != 0) {
                                sysinfo->is_heterogeneous = 1;
                                m->efficiency_cls = u.Processor->EfficiencyClass;
                        }

                        t &= ~BIT_ULL(curr_cpu);

                        // workaround to iterate cpu groups
                        if (curr_cpu == grp_nr_cpu)
                                curr_grp++;
                } while (1);

                break;
        }

        case RelationGroup:
        case RelationCache:
        case RelationNumaNode:
        case RelationNumaNodeEx:
        case RelationProcessorModule:
                break;

        default:
                pr_info("unknown Relationship=%x\n", pslpi->Relationship);
        }

        return 0;
}

void DumpLPI(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX pslpi)
{
        union {
                PPROCESSOR_RELATIONSHIP Processor;
                PNUMA_NODE_RELATIONSHIP NumaNode;
                PCACHE_RELATIONSHIP Cache;
                PGROUP_RELATIONSHIP Group;
        } u;

        u.Processor = &pslpi->Processor;

        switch (pslpi->Relationship) {
        case RelationProcessorPackage:
                pr_raw("RelationProcessorPackage(GroupCount = %u)\n", u.Processor->GroupCount);

                WORD GroupCount;
                if ((GroupCount = u.Processor->GroupCount))
                {
                        PGROUP_AFFINITY GroupMask = u.Processor->GroupMask;
                        do
                        {
                                pr_raw("group<%u> Mask = %016llx\n", GroupMask->Group, GroupMask->Mask);
                        } while (GroupMask++, --GroupCount);
                }
                break;

        case RelationProcessorCore:
                pr_raw("RelationProcessorCore(%x): Mask = %016llx\n", u.Processor->Flags, u.Processor->GroupMask->Mask);
                break;

        case RelationGroup:
                pr_raw("RelationGroup(%u/%u)\n", u.Group->ActiveGroupCount, u.Group->MaximumGroupCount);

                WORD ActiveGroupCount;
                if ((ActiveGroupCount = u.Group->ActiveGroupCount))
                {
                        PPROCESSOR_GROUP_INFO GroupInfo = u.Group->GroupInfo;
                        do
                        {
                                pr_raw("<%d/%d %016llx>\n",
                                        GroupInfo->ActiveProcessorCount,
                                        GroupInfo->MaximumProcessorCount,
                                        GroupInfo->ActiveProcessorMask);
                        } while (GroupInfo++, --ActiveGroupCount);
                }
                break;

        case RelationCache:
                pr_raw("Cache L%d (%x, %lx) %x\n", u.Cache->Level, u.Cache->LineSize, u.Cache->CacheSize, u.Cache->Type);
                break;

        case RelationNumaNode:
                pr_raw("NumaNode<%lu> (group = %d, mask = %016llx)\n", u.NumaNode->NodeNumber, u.NumaNode->GroupMask.Group, u.NumaNode->GroupMask.Mask);
                break;

        case RelationNumaNodeEx:
        case RelationProcessorModule:
                break;

        default:
                pr_raw("unknown Relationship=%x\n", pslpi->Relationship);
        }
}

int cpu_topology_dump(sys_info_t *sysinfo)
{
        DWORD sz = 0, info_sz;
        BOOL ok;
        void *buf, *__buf;
        int err = 0;

        GetLogicalProcessorInformationEx(RelationAll, NULL, &sz);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                pr_err("GetLogicalProcessorInformationEx() failed\n");
                return -EFAULT;
        }

        __buf = calloc(1, sz);
        if (!__buf) {
                pr_err("failed to allocate %lu bytes\n", sz);
                return -ENOMEM;
        }

        buf = __buf;

        ok = GetLogicalProcessorInformationEx(RelationAll, buf, &sz);
        if (!ok || !sz) {
                pr_err("GetLogicalProcessorInformationEx() failed, err = 0x%08x\n", (err = GetLastError()));
                goto out;
        }

        do {
                if ((err = cpu_topology_info_process(sysinfo, buf)))
                        goto out;

//                DumpLPI(buf);

                info_sz = ((SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *) buf)->Size;
                buf = (uint8_t *)buf + info_sz;
        } while (sz -= info_sz);

out:
        free(__buf);
        return err;
}

int sysinfo_init(sys_info_t *info)
{
        unsigned nr_grp = GetActiveProcessorGroupCount();
        ULONG nr_numa = 0;
        int err = 0;

        if (nr_grp == 0) {
                pr_err("GetActiveProcessorGroupCount() failed\n");
                return -EFAULT;
        }

        if (nr_grp < 2)
                pr_notice("active processor group count %u < 2\n", nr_grp);

        if (0 == GetNumaHighestNodeNumber(&nr_numa)) {
                pr_err("GetNumaHighestNodeNumber() failed\n");
                return -EFAULT;
        }

        info->nr_numa_node = nr_numa;

        info->nr_cpu_grp = nr_grp;
        info->cpu_grp = calloc(nr_grp, sizeof(struct cpu_grp_info));
        if (!info->cpu_grp)
                return -ENOMEM;

        for (unsigned i = 0; i < nr_grp; i++) {
                struct cpu_grp_info *grp_info = &info->cpu_grp[i];
                uint32_t cpu_cnt = GetMaximumProcessorCount(i);

                pr_info("cpu group %d has %u processors\n", i, cpu_cnt);

                grp_info->cpu_cnt = cpu_cnt;
                grp_info->cpu_mask = calloc(cpu_cnt, sizeof(struct cpu_mask));
                grp_info->grp_mask = GENMASK_ULL(cpu_cnt - 1, 0);
                if (!grp_info->cpu_mask)
                        return -ENOMEM;

                for (size_t j = 0; j < cpu_cnt; j++) {
                        struct cpu_mask *m = &grp_info->cpu_mask[j];
                        m->mask = BIT_ULL(j);
                }
        }

        if ((err = cpu_topology_dump(info)))
                return err;

        for (size_t i = 0; i < info->nr_cpu_grp; i++) {
                struct cpu_grp_info *grp = &info->cpu_grp[i];
                pr_raw("CPU GROUP: [%2zu] Mask: [0x%016jx]\n", i, grp->grp_mask);

                for (size_t j = 0; j < grp->cpu_cnt; j++) {
                        struct cpu_mask *m = &grp->cpu_mask[j];
                        pr_raw("CPU [%2zu] Mask: [0x%016jx] Relation: [0x%016jx]", j, m->mask, m->relation_mask);
                        if (info->is_heterogeneous) {
                                pr_raw(" [%s-Core]", m->efficiency_cls ? "P" : "E");
                        }
                        pr_raw("\n");
                }
        }

        return 0;
}

void sysinfo_deinit(sys_info_t *info)
{
        for (size_t i = 0; i < info->nr_cpu_grp; i++) {
                struct cpu_grp_info *grp = &info->cpu_grp[i];

                free(grp->cpu_mask);
        }

        free(info->cpu_grp);
}
