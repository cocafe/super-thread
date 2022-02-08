#include <stdint.h>

#include <windows.h>

#include "utils.h"
#include "logging.h"
#include "sysinfo.h"

#include <sysinfoapi.h>

sys_info_t g_sys_info = { 0 };

int cpu_topology_info_process(sys_info_t *sysinfo, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX pslpi)
{
        union {
                PPROCESSOR_RELATIONSHIP Processor;
                PNUMA_NODE_RELATIONSHIP NumaNode;
                PCACHE_RELATIONSHIP Cache;
                PGROUP_RELATIONSHIP Group;
        } u;
        static int32_t curr_grp = -1;

        u.Processor = &pslpi->Processor;

        switch (pslpi->Relationship) {
        case RelationProcessorPackage: {
                WORD GroupCount = u.Processor->GroupCount;
                PGROUP_AFFINITY GroupMask = u.Processor->GroupMask;

                if (GroupCount > 1) {
                        pr_err("unexpected: GroupCount %hu > 1\n", GroupCount);
                        return -EINVAL;
                }

//                do {
//                        pr_info("group<%u> Mask = %016llx\n", GroupMask->Group, GroupMask->Mask);
//                } while (GroupMask++, --GroupCount);

                sysinfo->cpu_grp[++curr_grp].grp_mask = GroupMask->Mask;
                break;
        }

        case RelationProcessorCore: {
                uint64_t relation_mask = u.Processor->GroupMask->Mask;
                uint64_t t = relation_mask;
                size_t curr_cpu;

                do {
                        struct cpu_mask *m;

                        curr_cpu = find_first_bit_u64(&t);

                        if (curr_cpu == 64)
                                break;

                        m = &(sysinfo->cpu_grp[curr_grp].cpu_mask[curr_cpu]);
                        m->relation_mask = relation_mask;

                        t &= ~BIT_ULL(curr_cpu);
                } while (1);

                break;
        }

        case RelationGroup:
        case RelationCache:
        case RelationNumaNode:
                break;

        default:
                pr_info("unknown Relationship=%x\n", pslpi->Relationship);
        }

        return 0;
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
        int err = 0;

        if (nr_grp == 0) {
                pr_err("GetActiveProcessorGroupCount() failed\n");
                return -EFAULT;
        }

        if (nr_grp < 2)
                pr_notice("active processor group count %u < 2\n", nr_grp);

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
                pr_info("CPU GROUP: [%2zu] MASK: [0x%016jx]\n", i, grp->grp_mask);

                for (size_t j = 0; j < grp->cpu_cnt; j++) {
                        struct cpu_mask *m = &grp->cpu_mask[j];
                        pr_info("CPU [%2zu] MASK: [0x%016jx] RELATION: [0x%016jx]\n", j, m->mask, m->relation_mask);
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
