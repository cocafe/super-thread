#ifndef SUPER_THREAD_USRCFG_H
#define SUPER_THREAD_USRCFG_H

enum proc_identify_type_opt {
        IDENTITY_NONE = 0,
        IDENTITY_PROCESS_EXE,
        IDENTITY_FILE_HANDLE,
        IDENTITY_CMDLINE,
};

enum proc_prio_opt {
        PROC_PRIO_UNCHANGED = 0,
        PROC_PRIO_REALTIME,
        PROC_PRIO_HIGH,
        PROC_PRIO_ABOVE_NORMAL,
        PROC_PRIO_NORMAL,
        PROC_PRIO_BELOW_NORMAL,
        PROC_PRIO_LOW,
        PROC_PRIO_IDLE
};

enum io_prio_opt {
        IO_PRIO_UNCHANGED = 0,
        IO_PRIO_HIGH,
        IO_PRIO_NORMAL,
        IO_PRIO_LOW,
        IO_PRIO_VERY_LOW,
};

enum proc_group_scheme_opt {
        PROC_GROUP_STATIC = 0,
        PROC_GROUP_BALANCE,
        PROC_GROUP_RANDOM,
};

enum thread_affinity_scheme_opt {
        THRD_AFFINITY_STATIC = 0,
        THRD_AFFINITY_BALANCE,
        THRD_AFFINITY_RANDOM,
};

struct profile_identity {
        uint32_t type;
        uint32_t filter;
        char    *value;
};

struct affinity_profile {
        uint32_t enabled;

        uint32_t proc_prio;
        uint32_t io_prio;

        struct {
                uint32_t node;
                uint32_t scheme;
        } proc_group;

        struct {
                uint64_t affinity;
                uint32_t scheme;
        } thread;

        struct profile_identity *id;

        struct list_head node;
};

struct usrcfg {
        uint32_t sampling_intv;
        struct affinity_profile *profiles;
};

typedef struct affinity_profile affinity_profile_t;

extern struct usrcfg g_cfg;

#endif //SUPER_THREAD_USRCFG_H
