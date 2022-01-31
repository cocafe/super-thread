#ifndef SUPER_THREAD_SUPERVISOR_H
#define SUPER_THREAD_SUPERVISOR_H

#include <tommy.h>
#include "myntapi.h"

#define PROC_HASH_TBL_BUCKET    (1024)
#define THRD_HASH_TBL_BUCKET    (1024)

#define NODE_MAP_SUPPORT_MASK   (GENMASK((MAX_PROC_GROUPS - 1), 0))

typedef struct proc_entry proc_entry_t;
typedef struct proc_info proc_info_t;
typedef struct thrd_entry thrd_entry_t;
typedef struct supervisor supervisor_t;
typedef struct supervisor_val supervisor_val_t;

struct thrd_entry {
        tommy_node      node;

        size_t          tid;
        size_t          pid;
        GROUP_AFFINITY  last_aff;
        uint32_t        last_update;
};

struct proc_info {
        wchar_t                 name[MAX_PATH];
        size_t                  pid;
        PROCESS_PRIORITY_CLASS  proc_prio __attribute__((aligned(4)));
        IO_PRIORITY_HINT        io_prio;
        GROUP_AFFINITY          curr_aff;
        uint8_t                 use_thread_affinity;
};

struct proc_entry {
        tommy_node      node;
//        tommy_hashtable threads;

        proc_info_t     info;

        profile_t      *profile;
        size_t          profile_idx;

        GROUP_AFFINITY  last_aff;

        uint8_t         is_new;

};

struct procs_sched {
        unsigned long node_map_next;
        unsigned long node_map_init;
};

// intermediate variables
struct supervisor_val {
        union {
                struct procs_sched procs_sched;
        } u;
};

struct supervisor {
        size_t            active_proc_grp; // TODO: move to system info

        pthread_t         tid_worker;
        tommy_hashtable   proc_selected;

        supervisor_val_t *vals;
        uint32_t          update_stamp;
};

int supervisor_init(supervisor_t *sv);
int supervisor_deinit(supervisor_t *sv);
int supervisor_run(supervisor_t *sv);

#endif //SUPER_THREAD_SUPERVISOR_H
