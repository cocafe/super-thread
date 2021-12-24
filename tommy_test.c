#include <tommy.h>

#include "logging.h"

struct obj {
        int value;
        tommy_node node;
};

void htable_iterator(void *data)
{
        struct obj *p = data;

        pr_info("obj: %p\n", p);
}

int tommy_hashit_test(void)
{
        tommy_hashtable table;
        struct obj objs[4] = { 0 };

        objs[0].value = 233;
        objs[1].value = 666;
        objs[2].value = 888;
        objs[3].value = 233;

        tommy_hashtable_init(&table, 1024);

        for (size_t i = 0; i < ARRAY_SIZE(objs); i++) {
                struct obj *p = &objs[i];
                pr_info("insert %p into hash table\n", p);
                tommy_hashtable_insert(&table, &p->node, p, tommy_inthash_u32(p->value));
        }

        {
                tommy_node *n = tommy_hashtable_bucket(&table, tommy_inthash_u32(233));

                while (n) {
                        struct obj *p = n->data;

                        pr_info("%p->value: %d\n", p, p->value);

                        n = n->next;
                }
        }

        {
                tommy_hashtable_foreach(&table, htable_iterator);
        }

        tommy_hashtable_done(&table);

        return 0;
}

