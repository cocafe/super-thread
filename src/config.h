#ifndef SUPER_THREAD_CONFIG_H
#define SUPER_THREAD_CONFIG_H

#include <minwindef.h>
#include <pthread.h>

#include "logging.h"

#define MAX_PROC_GROUPS                 (8)

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
        PROC_PRIO_IDLE,
        PROC_PRIO_NORMAL,
        PROC_PRIO_HIGH,
        PROC_PRIO_REALTIME,
        PROC_PRIO_BELOW_NORMAL,
        PROC_PRIO_ABOVE_NORMAL,
        NUM_PROC_PRIOS,
};

enum io_prio {
        IO_PRIO_UNCHANGED = 0,
        IO_PRIO_VERY_LOW,
        IO_PRIO_LOW,
        IO_PRIO_NORMAL,
        IO_PRIO_HIGH,
        NUM_IO_PRIOS,
};

enum proc_node_balance {
        PROC_BALANCE_BY_MAP = 0,
        PROC_BALANCE_RAND,
        PROC_BALANCE_RR,
        PROC_BALANCE_ONLOAD,
        NUM_PROC_BALANCE,
};

enum thread_balance {
        THRD_BALANCE_RAND = 0,
        THRD_BALANCE_NODE_RR,
        THRD_BALANCE_CPU_RR,
        THRD_BALANCE_ONLOAD,
        NUM_THRD_BALANCE,
};

enum supervisor_granularity {
        SUPERVISOR_PROCESSES = 0,
        SUPERVISOR_THREADS,
        NUM_SUPERVISOR_GRANS,
};

typedef struct profile profile_t;

struct proc_identity {
        uint32_t type;
        uint32_t filter;
        wchar_t *value;
};

struct supervisor_cfg {
        uint32_t node_map;
        uint32_t balance;
        uint64_t affinity;
};

struct profile {
        wchar_t                *name;

        uint32_t                enabled;

        uint32_t                proc_prio;
        uint32_t                io_prio;

        struct proc_identity   *id;
        size_t                  id_cnt;

        uint32_t                sched_mode;
        uint32_t                oneshot;
        struct supervisor_cfg   processes;
        struct supervisor_cfg   threads;
};

struct config {
        uint32_t        sampling_ms;
        uint32_t        loglvl[NUM_LOG_LEVELS];
        char            json_path[MAX_PATH];

        profile_t      *profiles;
        size_t          profile_cnt;
};

extern struct config g_cfg;

int usrcfg_init(void);
int usrcfg_deinit(void);
int usrcfg_apply(void);
int usrcfg_save(void);

#endif // SUPER_THREAD_CONFIG_H
