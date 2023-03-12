#ifndef SUPER_THREAD_CONFIG_H
#define SUPER_THREAD_CONFIG_H

#include <minwindef.h>
#include <pthread.h>

#include <libjj/logging.h>
#include <libjj/jkey.h>

#define SAMPLING_SEC_DEF                (10)
#define JSON_CFG_PATH_DEF               "config.json"

#define MAX_PROC_GROUPS                 (8)

enum tristate_val {
        LEAVE_AS_IS = 0,
        STRVAL_ENABLED,
        STRVAL_DISABLED,
        NUM_TRISTATE_VALS,
};

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

enum proc_prio_cls {
        PROC_PRIO_CLS_UNCHANGED = 0,
        PROC_PRIO_CLS_IDLE,
        PROC_PRIO_CLS_BELOW_NORMAL,
        PROC_PRIO_CLS_NORMAL,
        PROC_PRIO_CLS_ABOVE_NORMAL,
        PROC_PRIO_CLS_HIGH,
        PROC_PRIO_CLS_REALTIME,
        NUM_PROC_PRIO_CLASS,
};

enum thrd_prio_lvl {
        THRD_PRIO_LVL_UNCHANGED = 0,
        THRD_PRIO_LVL_IDLE,
        THRD_PRIO_LVL_LOWEST,
        THRD_PRIO_LVL_BELOW_NORMAL,
        THRD_PRIO_LVL_NORMAL,
        THRD_PRIO_LVL_ABOVE_NORMAL,
        THRD_PRIO_LVL_HIGHEST,
        THRD_PRIO_LVL_TIME_CRITICAL,
        NUM_THRD_PRIO_LEVELS,
};

enum io_prio {
        IO_PRIO_UNCHANGED = 0,
        IO_PRIO_VERY_LOW,
        IO_PRIO_LOW,
        IO_PRIO_NORMAL,
        IO_PRIO_HIGH,
        NUM_IO_PRIOS,
};

enum page_prio {
        PAGE_PRIO_UNCHANGED = 0,
        PAGE_PRIO_NORMAL,
        PAGE_PRIO_BELOW_NORMAL,
        PAGE_PRIO_MEDIUM,
        PAGE_PRIO_LOW,
        PAGE_PRIO_VERY_LOW,
        PAGE_PRIO_LOWEST,
        NUM_PAGE_PRIOS,
};

enum proc_node_balance {
        PROC_BALANCE_BY_MAP = 0,
        PROC_BALANCE_RAND,
        PROC_BALANCE_RR,
        PROC_BALANCE_ONLOAD,
        NUM_PROC_BALANCE,
};

enum thread_balance {
        THRD_BALANCE_NODE_RAND = 0,
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
        struct proc_identity *cmdl;
        struct proc_identity *file_hdl;
};

struct proc_cfg {
        uint32_t                prio_class;
        uint32_t                prio_boost;
        uint32_t                page_prio;
        uint32_t                io_prio;
};

struct thrd_cfg {
        uint32_t                prio_level;
        uint32_t                prio_level_least;
        uint32_t                prio_boost;

        uint32_t                page_prio;
        uint32_t                io_prio;
};

struct supervisor_cfg {
        uint32_t node_map;
        uint32_t balance;
        uint64_t affinity;
};

struct profile {
        wchar_t                *name;

        uint32_t                enabled;

        struct proc_identity   *id;
        size_t                  id_cnt;

        struct proc_cfg         proc_cfg;
        struct thrd_cfg         thrd_cfg;

        uint32_t                sched_mode;
        uint32_t                oneshot;
        uint32_t                always_set;
        uint32_t                delay;
        struct supervisor_cfg   processes;
        struct supervisor_cfg   threads;
};

struct config {
        uint32_t        sampling_sec;
        uint32_t        loglvl[NUM_LOG_LEVELS];
        char            json_path[MAX_PATH];

        profile_t      *profiles;
        size_t          profile_cnt;
};

extern struct config g_cfg;

extern char *cfg_identity_type_strs[];
extern char *cfg_identity_filter_strs[];
extern char *cfg_prio_cls_strs[];
extern char *cfg_prio_lvl_strs[];
extern char *cfg_page_prio_strs[];
extern char *cfg_io_prio_strs[];
extern char *cfg_proc_balance_strs[];
extern char *cfg_thrd_balance_strs[];
extern char *cfg_supervisor_mode_strs[];
extern char *cfg_tristate_strs[];

int usrcfg_init(void);
int usrcfg_deinit(void);
int usrcfg_apply(void);
int usrcfg_save(void);

#endif // SUPER_THREAD_CONFIG_H
