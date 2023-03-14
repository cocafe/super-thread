#ifndef SUPER_THREAD_SYSINFO_H
#define SUPER_THREAD_SYSINFO_H

typedef struct sys_info sys_info_t;

struct cpu_mask {
        uint64_t mask;
        uint64_t relation_mask;
        uint8_t efficiency_cls;
};

struct cpu_grp_info {
        uint64_t grp_mask;
        uint32_t cpu_cnt;
        struct cpu_mask *cpu_mask;
};

struct sys_info {
        uint32_t nr_cpu_grp;
        uint32_t nr_numa_node;
        uint32_t is_heterogeneous;
        struct cpu_grp_info *cpu_grp;
};

extern sys_info_t g_sys_info;

int sysinfo_init(sys_info_t *info);
void sysinfo_deinit(sys_info_t *info);

#endif // SUPER_THREAD_SYSINFO_H