#ifndef SUPER_THREAD_USRCFG_H
#define SUPER_THREAD_USRCFG_H

enum proc_identity_type {
        IDENTITY_NONE = 0,
        IDENTITY_PROCESS_EXE,
        IDENTITY_FILE_HANDLE,
        IDENTITY_CMDLINE,
        NUM_PROC_ID_TYPES,
};

enum proc_id_str_filter {
        STR_FILTER_IS = 0,
        STR_FILTER_CONTAIN,
        NUM_PROC_ID_STR_FILTERS,
};

enum proc_prio {
        PROC_PRIO_UNCHANGED = 0,
        PROC_PRIO_REALTIME,
        PROC_PRIO_HIGH,
        PROC_PRIO_ABOVE_NORMAL,
        PROC_PRIO_NORMAL,
        PROC_PRIO_BELOW_NORMAL,
        PROC_PRIO_LOW,
        PROC_PRIO_IDLE,
        NUM_PROC_PRIOS,
};

enum io_prio {
        IO_PRIO_UNCHANGED = 0,
        IO_PRIO_HIGH,
        IO_PRIO_NORMAL,
        IO_PRIO_LOW,
        IO_PRIO_VERY_LOW,
        NUM_IO_PRIOS,
};

enum proc_group_scheme {
        PROC_GROUP_STATIC = 0,
        PROC_GROUP_BALANCE,
        PROC_GROUP_RANDOM,
        PROC_GROUP_ROUND_ROBIN,
        NUM_PROC_GRP_SCHEMES,
};

enum thread_affinity_scheme {
        THRD_AFFINITY_STATIC = 0,
        THRD_AFFINITY_BALANCE,
        THRD_AFFINITY_RANDOM,
        NUM_THREAD_SCHEMES,
};

struct proc_identity {
        uint32_t type;
        uint32_t filter;
        char    *value;
};

struct profile {
        char *name;

        uint32_t enabled;
        uint32_t proc_prio;
        uint32_t io_prio;

        struct proc_identity *id;
        size_t id_cnt;

        struct {
                int32_t node;
                uint32_t scheme;
        } proc_grp;

        struct {
                uint64_t affinity;
                uint32_t scheme;
        } thread;
};

struct usrcfg {
        uint32_t sampling_ms;
        struct profile *profiles;
        size_t profile_cnt;
};

typedef struct profile profile_t;

extern struct usrcfg g_cfg;

int usrcfg_test(void);

#endif //SUPER_THREAD_USRCFG_H
