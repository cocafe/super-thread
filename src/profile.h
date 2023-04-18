#ifndef SUPER_THREAD_PROFILE_H
#define SUPER_THREAD_PROFILE_H

#define PROFILE_NAME_LEN                (128)
#define PROC_ID_VALUE_LEN               (128)

typedef struct profile profile_t;
typedef struct proc_identity proc_id_t;

struct proc_identity {
        struct list_head node;

        uint32_t type;
        uint32_t filter;
        char value[PROC_ID_VALUE_LEN];

        proc_id_t *cmdl;
        proc_id_t *file_hdl;
};

struct proc_cfg {
        uint32_t                prio_class;
        uint32_t                prio_boost;
        uint32_t                page_prio;
        uint32_t                io_prio;
        uint32_t                power_throttle;
};

struct thrd_cfg {
        uint32_t                prio_level;
        uint32_t                prio_level_least;
        uint32_t                prio_boost;

        uint32_t                page_prio;
        uint32_t                io_prio;
};

struct profile {
        struct list_head        node;
        struct hlist_node       hnode;

        char                    name[PROFILE_NAME_LEN];

        uint32_t                enabled;

        struct list_head        id_list;

        struct proc_cfg         proc_cfg;
        struct thrd_cfg         thrd_cfg;

        uint32_t                sched_mode;
        uint32_t                oneshot;
        uint32_t                always_set;
        uint32_t                delay;
        struct supervisor_cfg   processes;
        struct supervisor_cfg   threads;

        supervisor_val_t        sv;

        pthread_mutex_t         lock;
};

#define for_each_profile(t) list_for_each_entry((t), &g_cfg.profile_list, node)
#define for_each_profile_safe(t, s) list_for_each_entry_safe((t), (s), &g_cfg.profile_list, node)
#define for_each_profile_id(t, p) list_for_each_entry(t, &((p)->id_list), node)
#define for_each_profile_id_safe(t, s, p) list_for_each_entry_safe((t), (s), &((p)->id_list), node)

int profile_validate(profile_t *profile);
int profile_init(profile_t *profile);
int profile_lock(profile_t *profile);
int profile_try_lock(profile_t *profile);
int profile_unlock(profile_t *profile);
void profile_free(profile_t *profile);

void profile_hash_rebuild(void);
void profile_hash_del(profile_t *profile);
profile_t *profile_hash_get(profile_t *ptr);

void profiles_add(profile_t *profile);
void profiles_delete(profile_t *profile);

int loaded_profiles_init(void);

#endif // SUPER_THREAD_PROFILE_H