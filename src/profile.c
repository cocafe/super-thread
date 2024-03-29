#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libjj/logging.h>
#include <libjj/list.h>

#include "sysinfo.h"
#include "config.h"

static void affinity_mask_limit(struct supervisor_cfg *cfg)
{
        size_t nr_cpu_grp = g_sys_info.nr_cpu_grp;
        size_t cpu_cnt = g_sys_info.cpu_grp[0].cpu_cnt;
        uint32_t avail_node_map = GENMASK(nr_cpu_grp - 1, 0);
        uint32_t avail_affinity_map = GENMASK(cpu_cnt - 1, 0);

        cfg->node_map &= avail_node_map;
        cfg->affinity &= avail_affinity_map;
}

int profile_validate(profile_t *profile)
{
        if (profile->enabled == 0)
                pr_info("profile [%s] is disabled\n", profile->name);

        switch (profile->processes.balance) {
        case PROC_BALANCE_BY_MAP:
        case PROC_BALANCE_RAND:
        case PROC_BALANCE_RR:
                break;

        case PROC_BALANCE_ONLOAD:
                pr_info("onload balance algorithm is not implemented\n");
                break;

        default:
                pr_err("invalid balance mode\n");
                return -EINVAL;
        }

        switch (profile->threads.balance) {
        case THRD_BALANCE_NODE_RAND:
        case THRD_BALANCE_NODE_RR:
        case THRD_BALANCE_CPU_RR:
                break;

        case THRD_BALANCE_ONLOAD:
                pr_info("algorithm is not implemented\n");
                break;

        default:
                pr_err("invalid balance mode\n");
                return -EINVAL;
        }

        affinity_mask_limit(&profile->processes);
        affinity_mask_limit(&profile->threads);

        return 0;
}

static void __profile_init(profile_t *profile)
{
        pthread_mutexattr_init(&profile->lockattr);
        pthread_mutexattr_settype(&profile->lockattr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&profile->lock, &profile->lockattr);
        INIT_HLIST_NODE(&profile->hnode);
}

int profile_init(profile_t *profile)
{
        profile->enabled = 0;
        INIT_LIST_HEAD(&profile->node);
        INIT_LIST_HEAD(&profile->id_list);
        __profile_init(profile);
        affinity_mask_limit(&profile->processes);
        affinity_mask_limit(&profile->threads);

        return 0;
}

int profile_deinit(profile_t *profile)
{
        pthread_mutex_destroy(&profile->lock);
        pthread_mutexattr_destroy(&profile->lockattr);

        return 0;
}

void profile_free(profile_t *profile)
{
        proc_id_t *t, *s;

        for_each_profile_id_safe(t, s, profile) {
                free(t);
        }

        free(profile);
}

int profile_try_lock(profile_t *profile)
{
        return pthread_mutex_trylock(&profile->lock);
}

int profile_lock(profile_t *profile)
{
        return pthread_mutex_lock(&profile->lock);
}

int profile_unlock(profile_t *profile)
{
        return pthread_mutex_unlock(&profile->lock);
}

void profile_hash_rebuild(void)
{
        profile_t *p, *s;

        pthread_mutex_lock(&g_cfg.profile_hlist.lck);

        memset(g_cfg.profile_hlist.tbl, 0, sizeof(g_cfg.profile_hlist.tbl));
        hash_init(g_cfg.profile_hlist.tbl);

        for_each_profile_safe(p, s) {
                if (profile_try_lock(p))
                        continue;

                INIT_HLIST_NODE(&p->hnode);
                hash_add(g_cfg.profile_hlist.tbl, &p->hnode, (intptr_t)p);

                profile_unlock(p);
        }

        pthread_mutex_unlock(&g_cfg.profile_hlist.lck);
}

// to check profile is deleted or not
profile_t *profile_hash_get(profile_t *ptr)
{
        profile_t *p, *s;
        int valid = 0;

        pthread_mutex_lock(&g_cfg.profile_hlist.lck);

        hash_for_each_possible_safe(g_cfg.profile_hlist.tbl, p, s, hnode, (intptr_t)ptr) {
                if (p == ptr) {
                        valid = 1;
                        break;
                }
        }

        pthread_mutex_unlock(&g_cfg.profile_hlist.lck);

        return valid ? p : NULL;
}

void profile_hash_del(profile_t *profile)
{
        pthread_mutex_lock(&g_cfg.profile_hlist.lck);

        hash_del(&profile->hnode);

        pthread_mutex_unlock(&g_cfg.profile_hlist.lck);
}

void profile_list_add(profile_t *profile)
{
        list_add(&profile->node, &g_cfg.profile_list);
        profile_hash_rebuild();
}

void profile_list_delete(profile_t *profile)
{
        list_del(&profile->node);
        profile_hash_rebuild();
}

int loaded_profiles_init(void)
{
        struct list_head *t;

        list_for_each(t, &g_cfg.profile_list) {
                __profile_init(container_of(t, profile_t, node));
        }

        pthread_mutex_init(&g_cfg.profile_hlist.lck, NULL);
        profile_hash_rebuild();

        return 0;
}