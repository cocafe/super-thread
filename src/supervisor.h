#ifndef SUPER_THREAD_SUPERVISOR_H
#define SUPER_THREAD_SUPERVISOR_H

#include <pthread.h>
#include <semaphore.h>

#include <tommyds/tommy.h>

#include "myntapi.h"

#define PROC_HASH_TBL_BUCKET    (1024)
#define THRD_HASH_TBL_BUCKET    (1024)

#define NODE_MAP_SUPPORT_MASK   (GENMASK((MAX_PROC_GROUPS - 1), 0))

typedef struct proc_entry proc_entry_t;
typedef struct proc_info proc_info_t;
typedef struct thrd_entry thrd_entry_t;
typedef struct supervisor supervisor_t;
typedef struct supervisor_val supervisor_val_t;
typedef struct profile profile_t;

struct supervisor_cfg {
        uint32_t node_map;
        uint32_t balance;
        uint64_t affinity;
};

struct thrd_entry {
        tommy_node      node;

        size_t          tid;
        size_t          pid;
        GROUP_AFFINITY  last_aff;
        uint32_t        last_stamp;

        // track change time
};

struct proc_info {
        wchar_t                 name[_MAX_FNAME];
        size_t                  pid;
        BOOL                    prio_boost;
        PROCESS_PRIORITY_CLASS  prio_class __attribute__((aligned(4)));
        IO_PRIORITY_HINT        io_prio;
        ULONG                   page_prio;
        GROUP_AFFINITY          curr_aff;
        uint8_t                 is_threaded;
};

struct proc_entry {
        tommy_node      node;
        tommy_hashtable threads;

        proc_info_t     info;

        profile_t      *profile;

        GROUP_AFFINITY  last_aff;
        uint32_t        last_stamp;
        uint32_t        on_stamp;

        uint8_t         is_new;
        uint8_t         oneshot;
        uint8_t         always_set;
};

struct procs_sched {
        unsigned long node_map_next;
};

struct thrds_sched {
        unsigned long node_map_next;
        unsigned long cpu_map_next;
};

// intermediate variables
struct supervisor_val {
        union {
                struct procs_sched procs_sched;
                struct thrds_sched thrds_sched;
        } u;
};

struct supervisor {
        pthread_t         tid_worker;
        pthread_mutex_t   trigger_lck;
        sem_t             sleeper;

        tommy_hashtable   proc_selected;

        uint32_t          update_stamp;
        uint8_t           paused;
};

extern supervisor_t g_sv;

int supervisor_init(supervisor_t *sv);
int supervisor_deinit(supervisor_t *sv);
int supervisor_run(supervisor_t *sv);
void supervisor_trigger_once(supervisor_t *sv);

void proc_entry_list_dump(tommy_hashtable *tbl, profile_t *profile);

#endif //SUPER_THREAD_SUPERVISOR_H
