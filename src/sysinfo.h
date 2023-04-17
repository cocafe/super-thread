#ifndef SUPER_THREAD_SYSINFO_H
#define SUPER_THREAD_SYSINFO_H

#include <winnt.h>

#define CACHE_LEVEL_MAX                 (4)

enum cache_type {
        CACHE_UNIFIED,
        CACHE_INSTRUCTION,
        CACHE_DATA,
        CACHE_TRACE,
        NUM_CACHE_TYPES,
};

typedef struct sys_info sys_info_t;

struct cache_info {
        uint32_t type;
        size_t size;
        uint64_t relation_mask;
};

struct cpu_info {
        uint64_t mask;
        uint64_t relation_mask;
        uint8_t efficiency_cls;
        struct {
                struct cache_info _[NUM_CACHE_TYPES];
        } cache[CACHE_LEVEL_MAX];
};

struct cpu_grp_info {
        uint64_t grp_mask;
        uint32_t cpu_cnt;
        struct cpu_info *cpu;
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