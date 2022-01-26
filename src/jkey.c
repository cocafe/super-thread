#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include "list.h"
#include "jkey.h"
#include "logging.h"

static uint32_t jkey_to_cjson_type[] = {
        [JKEY_TYPE_UNKNOWN]      = cJSON_Invalid,
        [JKEY_TYPE_OBJECT]       = cJSON_Object,
        [JKEY_TYPE_RO_ARRAY]     = cJSON_Array,
        [JKEY_TYPE_FIXED_ARRAY]  = cJSON_Array,
        [JKEY_TYPE_GROW_ARRAY]   = cJSON_Array,
        [JKEY_TYPE_LIST_ARRAY]   = cJSON_Array,
        [JKEY_TYPE_STRREF]       = cJSON_String,
        [JKEY_TYPE_STRBUF]       = cJSON_String,
        [JKEY_TYPE_STRPTR]       = cJSON_String,
        [JKEY_TYPE_BOOL]         = cJSON_Boolean,
        [JKEY_TYPE_INT]          = cJSON_Number,
        [JKEY_TYPE_UINT]         = cJSON_Number,
        [JKEY_TYPE_DOUBLE]       = cJSON_Number,
        [NUM_JKEY_TYPES]         = cJSON_Invalid,
};

char *jkey_type_strs[] = {
        [JKEY_TYPE_UNKNOWN]      = "unknown",
        [JKEY_TYPE_OBJECT]       = "object",
        [JKEY_TYPE_RO_ARRAY]     = "readonly_array",
        [JKEY_TYPE_FIXED_ARRAY]  = "fixed_array",
        [JKEY_TYPE_GROW_ARRAY]   = "grow_array",
        [JKEY_TYPE_LIST_ARRAY]   = "list_array",
        [JKEY_TYPE_STRREF]       = "string_ref",
        [JKEY_TYPE_STRBUF]       = "string_buf",
        [JKEY_TYPE_STRPTR]       = "string_ptr",
        [JKEY_TYPE_BOOL]         = "bool",
        [JKEY_TYPE_INT]          = "int",
        [JKEY_TYPE_UINT]         = "uint",
        [JKEY_TYPE_DOUBLE]       = "double",
};

static unsigned is_jkey_writable_array(jkey_t *jkey)
{
        return is_cjson_type(jkey->cjson_type, cJSON_Array) &&
               jkey->type != JKEY_TYPE_RO_ARRAY;
}

static unsigned is_jkey_compound(jkey_t *jkey)
{
        return is_cjson_type(jkey->cjson_type, cJSON_Compound);
}

static int jbuf_grow(jbuf_t *b, size_t jk_cnt)
{
        size_t offset, new_sz;
        void *t;

        if (!b)
                return -EINVAL;

        if (!b->base)
                return -ENODATA;

        offset = (uint8_t *)b->head - (uint8_t *)b->base;
        new_sz = b->alloc_sz + (jk_cnt * sizeof(jkey_t));

        b->base = realloc_safe(b->base, b->alloc_sz, new_sz);
        if (!b->base)
                return -ENOMEM;

        b->alloc_sz = new_sz;
        b->head = (uint8_t *)b->base + offset;
        b->end  = (uint8_t *)b->base + b->alloc_sz;

        return 0;
}

static int jbuf_head_next(jbuf_t *b)
{
        int err = 0;

        if (!b)
                return -EINVAL;

        if (!b->base || !b->head)
                return -ENODATA;

        if ((uint8_t *)b->head + sizeof(jkey_t) > (uint8_t *)b->end)
                if ((err = jbuf_grow(b, 10)))
                        return err;

        b->head = (uint8_t *)b->head + sizeof(jkey_t);

        return 0;
}

int __jbuf_key_add(jbuf_t *b, uint32_t type, jkey_t **curr)
{
        jkey_t *k;
        size_t offset;
        int err;

        if (!b)
                return -EINVAL;

        if (!b->base || !b->head)
                return -ENODATA;

        if (type >= NUM_JKEY_TYPES)
                return -EINVAL;

        offset = (size_t)b->head - (size_t)b->base;

        if ((err = jbuf_head_next(b)))
                return err;

        k = (void *)((uint8_t *)b->base + offset);
        k->type = type;
        k->cjson_type = jkey_to_cjson_type[type];

        if (curr)
                *curr = k;

        return 0;
}

void *jbuf_key_add(jbuf_t *b, int type, char *key, void *ref, size_t sz)
{
        jkey_t *k;
        int err;

        if ((err = __jbuf_key_add(b, type, &k))) {
                pr_err("err = %d\n", err);
                return NULL;
        }

        if (key && key[0] != '\0')
                k->key = key;

        k->data.ref = ref;
        k->data.sz = sz;

        return (void *)((uint8_t *)k - (uint8_t *)b->base);
}

jkey_t *jbuf_key_get(jbuf_t *b, void *cookie)
{
        return (jkey_t *)((uint8_t *)b->base + (size_t)cookie);
}

jkey_t *jbuf_root_key_get(jbuf_t *b)
{
        return (void *)b->base;
}

static jkey_t *jkey_array_data_key_get(jkey_t *arr)
{
        if (!is_cjson_type(arr->cjson_type, cJSON_Array))
                return NULL;

        if (arr->child_cnt == 0)
                return NULL;

        return &(((jkey_t *)arr->child)[0]);
}

static void jkey_strptr_set(jbuf_t *b, void *cookie)
{
        jkey_t *k = jbuf_key_get(b, cookie);
        k->data.sz = 0;
        k->data.ref_ptr = 1;
        k->data.ref_malloc = 1;
}

void jkey_int_base_set(jbuf_t *b, void *cookie, uint8_t int_base)
{
        jkey_t *k;

        k = jbuf_key_get(b, cookie);
        k->data.int_base = int_base;
        k->cjson_type = cJSON_String;
}

void jkey_ref_parent_set(jbuf_t *b, void *cookie, ssize_t offset)
{
        jkey_t *k;

        k = jbuf_key_get(b, cookie);
        k->data.ref_offs = offset;
        k->data.ref_parent = 1;
}

void jkey_base_ref_parent_set(jbuf_t *b, void *cookie, ssize_t offset)
{
        jkey_t *k;

        k = jbuf_key_get(b, cookie);
        k->obj.base_ref_offs = offset;
        k->obj.base_ref_parent = 1;
}

void *jbuf_obj_open(jbuf_t *b, char *key)
{
        return jbuf_key_add(b, JKEY_TYPE_OBJECT, key, NULL, 0);
}

void *jbuf_objptr_open(jbuf_t *b, char *key, void *ref, size_t sz)
{
        jkey_t *k;
        void *cookie = jbuf_key_add(b, JKEY_TYPE_OBJECT, key, NULL, sz);
        if (!cookie)
                return NULL;

        k = jbuf_key_get(b, cookie);
        k->obj.base_ref = ref;
        k->obj.base_ref_ptr = 1;
        k->obj.base_ref_malloc = 1;

        return cookie;
}

void jbuf_obj_close(jbuf_t *b, void *cookie)
{
        jkey_t *k = (void *)((size_t)b->base + (size_t)cookie);
        size_t len = ((size_t)b->head - (size_t)k - sizeof(jkey_t));

        k->child_cnt = len / sizeof(jkey_t);
}

void *jbuf_arr_open(jbuf_t *b, char *key)
{
        return jbuf_key_add(b, JKEY_TYPE_RO_ARRAY, key, NULL, 0);
}

void *jbuf_fixed_arr_open(jbuf_t *b, char *key)
{
        return jbuf_key_add(b, JKEY_TYPE_FIXED_ARRAY, key, NULL, 0);
}

void *jbuf_grow_arr_open(jbuf_t *b, char *key)
{
        return jbuf_key_add(b, JKEY_TYPE_GROW_ARRAY, key, NULL, 0);
}

void *jbuf_list_arr_open(jbuf_t *b, char *key)
{
        return jbuf_key_add(b, JKEY_TYPE_LIST_ARRAY, key, NULL, 0);
}

void jbuf_arr_close(jbuf_t *b, void *cookie)
{
        return jbuf_obj_close(b, cookie);
}

void __jbuf_fixed_arr_setup(jbuf_t *b, void *cookie, void *ref, size_t ele_cnt, size_t ele_sz, int base_ref_ptr)
{
        jkey_t *k = jbuf_key_get(b, cookie);

        k->obj.base_ref                 = ref;
        k->obj.sz                       = ele_sz;
        k->obj.arr.fixed.ele_cnt        = ele_cnt;

        if (base_ref_ptr) {
                k->obj.base_ref_ptr     = 1;
                k->obj.base_ref_malloc  = 1;
        }
}

void jbuf_fixed_arr_setup(jbuf_t *b, void *cookie, void *ref, size_t ele_cnt, size_t ele_sz)
{
        __jbuf_fixed_arr_setup(b, cookie, ref, ele_cnt, ele_sz, 0);
}

void jbuf_fixed_arrptr_setup(jbuf_t *b, void *cookie, void **ref, size_t ele_cnt, size_t ele_sz)
{
        __jbuf_fixed_arr_setup(b, cookie, ref, ele_cnt, ele_sz, 1);
}

void jbuf_offset_fixed_arr_setup(jbuf_t *b, void *cookie, ssize_t offset, size_t ele_cnt, size_t ele_sz)
{
        __jbuf_fixed_arr_setup(b, cookie, NULL, ele_cnt, ele_sz, 0);
        jkey_base_ref_parent_set(b, cookie, offset);
}

void jbuf_grow_arr_setup(jbuf_t *b, void *cookie, void **ref, size_t *ext_ele_cnt, size_t ele_sz)
{
        jkey_t *k = jbuf_key_get(b, cookie);

        k->data.ref                     = NULL;
        k->obj.base_ref                 = ref;
        k->obj.base_ref_ptr             = 1;
        k->obj.base_ref_malloc          = 1;
        k->obj.sz                       = ele_sz;
        k->obj.arr.grow.alloc_cnt       = 0;
        k->obj.arr.grow.ext_ele_cnt     = ext_ele_cnt;
}

void jbuf_offset_grow_arr_setup(jbuf_t *b, void *cookie, ssize_t offset, ssize_t ext_ele_cnt_offs, size_t ele_sz)
{
        jkey_t *k = jbuf_key_get(b, cookie);

        jbuf_grow_arr_setup(b, cookie, NULL, NULL, ele_sz);
        jkey_base_ref_parent_set(b, cookie, offset);

        k->obj.arr.grow.ext_ele_cnt_offs = ext_ele_cnt_offs;
}

/**
 * jbuf_list_arr_setup() - describe list array, open array first
 *
 * @param b: jbuf
 * @param cookie: list array cookie
 * @param head: pointer to external list_head, the entry point of list
 * @param ctnr_sz: size of container which holds sub list_head to be allocated
 * @param offsof_ctnr_head: offset of list_head in container
 * @param ctnr_data_sz: size of data to write in container, for data key
 * @param offsof_ctnr_data: offset of data in container to write, for data key
 */
void jbuf_list_arr_setup(jbuf_t *b,
                         void *cookie,
                         struct list_head *head,
                         size_t ctnr_sz,
                         ssize_t offsof_ctnr_head,
                         size_t ctnr_data_sz,
                         ssize_t offsof_ctnr_data)
{
        jkey_t *k = jbuf_key_get(b, cookie);

        k->data.ref                     = NULL;
        k->data.sz                      = ctnr_data_sz;
        k->obj.base_ref                 = head;
        k->obj.base_ref_ptr             = 0;
        k->obj.base_ref_malloc          = 0;
        k->obj.sz                       = ctnr_sz;
        k->obj.arr.list.offs_head       = offsof_ctnr_head;
        k->obj.arr.list.offs_data       = offsof_ctnr_data;
        k->obj.arr.list.head_inited     = 0;

        if (head) {
                INIT_LIST_HEAD(head);
                k->obj.arr.list.head_inited = 1;
        }
}

void jbuf_offset_list_arr_setup(jbuf_t *b,
                                void *cookie,
                                ssize_t offsof_head_in_parent,
                                size_t ctnr_sz,
                                ssize_t offsof_ctnr_head,
                                size_t ctnr_data_sz,
                                ssize_t offsof_ctnr_data)
{
        jbuf_list_arr_setup(b, cookie, NULL, ctnr_sz, offsof_ctnr_head, ctnr_data_sz, offsof_ctnr_data);
        jkey_base_ref_parent_set(b, cookie, offsof_head_in_parent);
}

// external ref (read) only char*
void *jbuf_strref_add(jbuf_t *b, char *key, char *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_STRREF, key, ref, 0);
}

// external static size char[] buf
void *jbuf_strbuf_add(jbuf_t *b, char *key, char *ref, size_t len)
{
        return jbuf_key_add(b, JKEY_TYPE_STRBUF, key, ref, len);
}

// alloc internally char* for input
void *jbuf_strptr_add(jbuf_t *b, char *key, char **ref)
{
        void *cookie;

        cookie = jbuf_key_add(b, JKEY_TYPE_STRPTR, key, ref, 0);
        if (!cookie)
                return NULL;

        jkey_strptr_set(b, cookie);

        return cookie;
}

void *jbuf_strval_add(jbuf_t *b, char *key, uint32_t *ref, char *map[], size_t map_cnt)
{
        jkey_t *k;
        void *cookie = jbuf_key_add(b, JKEY_TYPE_UINT, key, ref, sizeof(uint32_t));
        if (!cookie)
                return NULL;

        k = jbuf_key_get(b, cookie);
        k->strval.map = map;
        k->strval.cnt = map_cnt;
        k->cjson_type = cJSON_String;

        return cookie;
}

void *jbuf_u8_add(jbuf_t *b, char *key, uint8_t *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_UINT, key, ref, sizeof(uint8_t));
}

void *jbuf_u16_add(jbuf_t *b, char *key, uint16_t *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_UINT, key, ref, sizeof(uint16_t));
}

void *jbuf_u32_add(jbuf_t *b, char *key, uint32_t *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_UINT, key, ref, sizeof(uint32_t));
}

void *jbuf_u64_add(jbuf_t *b, char *key, uint64_t *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_UINT, key, ref, sizeof(uint64_t));
}

void *jbuf_s8_add(jbuf_t *b, char *key, int8_t *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_INT, key, ref, sizeof(int8_t));
}

void *jbuf_s16_add(jbuf_t *b, char *key, int16_t *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_INT, key, ref, sizeof(int16_t));
}

void *jbuf_s32_add(jbuf_t *b, char *key, int32_t *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_INT, key, ref, sizeof(int32_t));
}

void *jbuf_s64_add(jbuf_t *b, char *key, int64_t *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_INT, key, ref, sizeof(int64_t));
}

void *jbuf_double_add(jbuf_t *b, char *key, double *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_DOUBLE, key, ref, sizeof(double));
}

void *jbuf_bool_add(jbuf_t *b, char *key, jkey_bool_t *ref)
{
        return jbuf_key_add(b, JKEY_TYPE_BOOL, key, ref, sizeof(jkey_bool_t));
}

void *jbuf_hex_u32_add(jbuf_t *b, char *key, uint32_t *ref)
{
        void *cookie = jbuf_u32_add(b, key, ref);
        if (!cookie)
                return NULL;

        jkey_int_base_set(b, cookie, 16);

        return cookie;
}

void *jbuf_hex_u64_add(jbuf_t *b, char *key, uint64_t *ref)
{
        void *cookie = jbuf_u64_add(b, key, ref);
        if (!cookie)
                return NULL;

        jkey_int_base_set(b, cookie, 16);

        return cookie;
}

void *jbuf_hex_s32_add(jbuf_t *b, char *key, int32_t *ref)
{
        void *cookie = jbuf_s32_add(b, key, ref);
        if (!cookie)
                return NULL;

        jkey_int_base_set(b, cookie, 16);

        return cookie;
}

void *jbuf_hex_s64_add(jbuf_t *b, char *key, int64_t *ref)
{
        void *cookie = jbuf_s64_add(b, key, ref);
        if (!cookie)
                return NULL;

        jkey_int_base_set(b, cookie, 16);

        return cookie;
}

void *jbuf_offset_strbuf_add(jbuf_t *b, char *key, ssize_t offset, size_t len)
{
        void *cookie = jbuf_strbuf_add(b, key, NULL, len);
        if (!cookie)
                return NULL;

        jkey_ref_parent_set(b, cookie, offset);

        return cookie;
}

void *jbuf_offset_strval_add(jbuf_t *b, char *key, ssize_t offset, char *map[], size_t map_cnt)
{
        void *cookie = jbuf_strval_add(b, key, NULL, map, map_cnt);
        if (!cookie)
                return NULL;

        jkey_ref_parent_set(b, cookie, offset);

        return cookie;
}

static inline void jkey_data_ptr_deref(jkey_t *jkey, void **out, size_t new_sz)
{
        *out = NULL;

        if (jkey->data.ref_ptr) {
                void *data_ref = *(uint8_t **)jkey->data.ref;

                if (NULL == jkey->data.ref)
                        return;

                if (NULL == data_ref && jkey->data.ref_malloc) {
                        size_t data_sz = jkey->data.sz;

                        if (new_sz)
                                data_sz = new_sz;

                        if (data_sz == 0)
                                return;

                        data_ref = calloc(1, data_sz);
                        if (NULL == data_ref)
                                return;

                        if (new_sz)
                                jkey->data.sz = new_sz;

                        *(uint8_t **)jkey->data.ref = data_ref;
                }

                *out = *(uint8_t **)jkey->data.ref;

                return;
        }

        // @data.ref points to actual data
        *out = jkey->data.ref;
}

static int jkey_bool_write(jkey_t *jkey, cJSON *node)
{
        uint32_t val = (node->type == cJSON_True) ? 1 : 0;
        void *dst = NULL;

        if (jkey->data.sz != sizeof(uint32_t)) {
                pr_err("data size %zu of key [%s] failed sanity check\n", jkey->data.sz, jkey->key);
                return -EFAULT;
        }

        jkey_data_ptr_deref(jkey, &dst, 0);
        if (!dst) {
                pr_err("data pointer is NULL\n");
                return -ENODATA;
        }

        return ptr_word_write(dst, jkey->data.sz, val);
}

static int jkey_int_write(jkey_t *jkey, cJSON *node)
{
        double val = cJSON_GetNumberValue(node);
        void *dst = NULL;

        if (isnan(val)) {
                pr_err("key [%s] failed to get number from cJSON\n", jkey->key);
                return -EFAULT;
        }

        if (jkey->data.sz == 0) {
                pr_err("data size %zu of key [%s] failed sanity check\n", jkey->data.sz, jkey->key);
                return -EFAULT;
        }

        jkey_data_ptr_deref(jkey, &dst, 0);
        if (!dst) {
                pr_err("data pointer is NULL\n");
                return -ENODATA;
        }

        return ptr_word_write(dst, jkey->data.sz, (int64_t)val);
}

static int jkey_float_write(jkey_t *jkey, cJSON *node)
{
        double val = cJSON_GetNumberValue(node);
        void *dst = NULL;

        if (isnan(val)) {
                pr_err("key [%s] failed to get number from cJSON\n", jkey->key);
                return -EFAULT;
        }

        if (jkey->data.sz != sizeof(double)) {
                pr_err("data size %zu of key [%s] failed sanity check\n", jkey->data.sz, jkey->key);
                return -EFAULT;
        }

        jkey_data_ptr_deref(jkey, &dst, 0);
        if (!dst) {
                pr_err("data pointer is NULL\n");
                return -ENODATA;
        }

#ifdef __ARM_ARCH_7A__
        if (likely((size_t)dst % sizeof(double))) {
                *(double *)dst = val;
        } else {
                pr_warn("float point unaligned access detected, fix your struct\n");
                memcpy(dst, &(double){ val }, sizeof(double));
        }
#else
        *(double *)dst = val;
#endif

        return 0;
}

static int strval_map_to_int(void *dst, size_t dst_sz, char *src, char **map, size_t map_sz)
{
        size_t src_len;

        src_len = strlen(src);

        for (uint64_t i = 0; i < map_sz; i++) {
                char *item = map[i];
                size_t item_len = strlen(item);

                if (src_len != item_len)
                        continue;

                if (!strncasecmp(item, src, __min(item_len, src_len))) {
                        return ptr_word_write(dst, dst_sz, (int64_t)i);
                }
        }

        pr_err("cannot convert string \'%s\' to value\n", src);

        return -ENOENT;
}

static inline int jkey_is_strptr(jkey_t *jkey)
{
        return jkey->type == JKEY_TYPE_STRPTR;
}

static int jkey_string_write(jkey_t *jkey, cJSON *node)
{
        char *json_str = cJSON_GetStringValue(node);
        size_t json_len, copy_len;
        void *dst = NULL;

        if (!json_str) {
                pr_err("key [%s] failed to get string from cJSON\n", jkey->key);
                return -EFAULT;
        }

        json_len = strlen(json_str);

        if (json_str[0] == '\0') {
                pr_verbose("key [%s] got empty string\n", jkey->key);
                return 0;
        }

        // + 2 : not always copy precisely
        jkey_data_ptr_deref(jkey, &dst, jkey_is_strptr(jkey) ? json_len + 2 : 0);
        if (!dst) {
                pr_err("data pointer is NULL\n");
                return -ENODATA;
        }

        switch (jkey->type) {
        case JKEY_TYPE_INT:
        case JKEY_TYPE_UINT:
                if (jkey->data.int_base) {
                        uint64_t t = strtoull(json_str, NULL, jkey->data.int_base);
                        return ptr_word_write(dst, jkey->data.sz, t);
                } else if (jkey->strval.map) {
                        return strval_map_to_int(dst, jkey->data.sz, json_str,
                                                 jkey->strval.map,
                                                 jkey->strval.cnt);
                } else {
                        pr_err("cannot convert string to number for key [%s]\n", jkey->key);
                        return -EINVAL;
                }

                break;

        case JKEY_TYPE_STRREF:
        case JKEY_TYPE_STRBUF:
        case JKEY_TYPE_STRPTR:
                if (jkey->data.sz == 0) {
                        pr_err("key [%s] string data has not allocated\n", jkey->key);
                        return -ENODATA;
                }

                copy_len = __min(jkey->data.sz, json_len);
                strncpy(dst, json_str, copy_len);

//                pr_verbose("key [%s] copy_len: %zu\n", jkey->key, copy_len);

                break;

        default:
                pr_err("invalid jkey type: %d, key [%s]\n", jkey->type, jkey->key);
                return -EINVAL;
        }

        return 0;
}

int jkey_value_write(jkey_t *jkey, cJSON *node)
{
        int err;

        switch (node->type) {
        case cJSON_True:
        case cJSON_False:
                err = jkey_bool_write(jkey, node);
                break;

        case cJSON_String:
                err = jkey_string_write(jkey, node);
                break;

        case cJSON_Number:
                switch (jkey->type) {
                case JKEY_TYPE_DOUBLE:
                        err = jkey_float_write(jkey, node);
                        break;

                case JKEY_TYPE_INT:
                case JKEY_TYPE_UINT:
                        err = jkey_int_write(jkey, node);
                        break;

                default:
                        err = -EFAULT;
                        break;
                }
                break;

        default:
                pr_err("unsupported cjson type %u for key [%s]\n", node->type, jkey->key);
                err = -EINVAL;
                break;
        }

        return err;
}

int jkey_cjson_input(jkey_t *jkey, cJSON *node)
{
        if (!jkey || !node)
                return 0;

        if (is_jkey_compound(jkey))
                return 0;

        if (!jkey->data.ref) {
                pr_dbg("key [%s] data ref is NULL\n", jkey->key);
                return 0;
        }

        return jkey_value_write(jkey, node);
}

static int is_jkey_cjson_node_match(jkey_t *jkey, cJSON *node)
{
        int jkey_named = jkey->key ? 1 : 0;
        int node_named = node->string ? 1 : 0;

        if (0 == is_cjson_type(jkey->cjson_type, node->type))
                return 0;

        if (0 != (jkey_named ^ node_named))
                return 0;

        if (jkey_named && node_named) {
                size_t strlen_jkey = strlen(jkey->key);
                size_t strlen_node = strlen(node->string);

                if (strlen_jkey != strlen_node)
                        return 0;

                if (0 != strncmp(jkey->key,
                                 node->string,
                                 strlen_jkey))
                        return 0;
        }

        return 1; // matched
}

static int jkey_array_key_check(jkey_t *arr)
{
        if (arr->type != JKEY_TYPE_FIXED_ARRAY &&
            arr->type != JKEY_TYPE_GROW_ARRAY &&
            arr->type != JKEY_TYPE_LIST_ARRAY)
                return -ECANCELED;

        if (arr->child_cnt == 0) {
                pr_err("array key [%s] does not have any child keys to parse itself\n", arr->key);
                return -EINVAL;
        }

        if (arr->obj.base_ref == NULL) {
                pr_notice("array key [%s] did not define data reference\n", arr->key);
                return -EINVAL;
        }

        if (arr->obj.sz == 0) {
                pr_err("array key [%s] element size is 0\n", arr->key);
                return -EINVAL;
        }

        return 0;
}

static int jkey_array_data_key_check(jkey_t *arr_key, jkey_t *data_key)
{
        if (!data_key->data.ref_parent && !data_key->obj.base_ref_parent) {
                pr_err("array [%s] data key should ref its parent\n", arr_key->key);
                return -EINVAL;
        }

        return 0;
}

static int jkey_base_ref_alloc(jkey_t *jkey, size_t base_sz)
{
        void *base_ref;

        if (!jkey->obj.base_ref ||
            !jkey->obj.base_ref_ptr ||
            !jkey->obj.base_ref_malloc)
                return 0;

        if (!base_sz) {
                pr_err("key [%s] allocate size is 0\n", jkey->key);
                return -EINVAL;
        }

        base_ref = *((uint8_t **)jkey->obj.base_ref);

        if (base_ref != NULL) {
                return 0;
        }

        base_ref = calloc(1, base_sz);
        if (!base_ref)
                return -ENOMEM;

        *((uint8_t **)jkey->obj.base_ref) = base_ref;

        return 0;
}

static int jkey_fixed_array_alloc(jkey_t *arr) {
        int err;
        size_t base_sz = arr->obj.arr.fixed.ele_cnt * arr->obj.sz;

        if (!arr->obj.arr.fixed.ele_cnt) {
                pr_err("array [%s] did not define max element cnt\n", arr->key);
                return -EINVAL;
        }

        err = jkey_base_ref_alloc(arr, base_sz);
        if (err == -ENOMEM) {
                pr_err("array [%s] failed to allocate %zu bytes\n",
                       arr->key, base_sz);
                return err;
        }

        return err;
}

static int jkey_fixed_grow_array_ref_update(jkey_t *arr_key, jkey_t *data_key, size_t idx)
{
        size_t idx_offset = arr_key->obj.sz * idx;
        void *base_ref = arr_key->obj.base_ref;

        if (0 == arr_key->obj.sz) {
                pr_err("array [%s] invalid element size\n", arr_key->key);
                return -EINVAL;
        }

        if (arr_key->obj.base_ref_ptr)
                base_ref = *((uint8_t **)arr_key->obj.base_ref);

        if (base_ref == NULL) {
                pr_dbg("array [%s] points to NULL\n", arr_key->key);
                return -ENODATA;
        }

        if (data_key->data.ref_parent)
                data_key->data.ref = base_ref + idx_offset;

        if (data_key->obj.base_ref_parent)
                data_key->obj.base_ref = base_ref + idx_offset;

        return 0;
}

static int jkey_grow_array_realloc(jkey_t *arr, size_t idx)
{
        size_t need_alloc = arr->obj.arr.grow.alloc_cnt + JBUF_GROW_ARR_REALLOC_INCR;
        size_t new_sz = need_alloc * arr->obj.sz;
        void *base_ref, *t;

        if (idx < arr->obj.arr.grow.alloc_cnt) {
                return 0;
        }

        if (!arr->obj.base_ref_ptr || !arr->obj.base_ref || !arr->obj.sz) {
                pr_err("invalid grow array [%s]\n", arr->key);
                return -EINVAL;
        }

        base_ref = *(uint8_t **)arr->obj.base_ref;
        if (base_ref == NULL) {
                if (!arr->obj.base_ref_malloc) {
                        pr_err("array [%s] refer NULL pointer and not do_malloc\n", arr->key);
                        return -EINVAL;
                }

                base_ref = calloc(1, new_sz);
                if (!base_ref) {
                        pr_err("array [%s] failed to allocate %zu bytes\n", arr->key, new_sz);
                        return -ENOMEM;
                }

        } else { // if in management routine, do realloc()
                size_t *extern_ele_cnt = arr->obj.arr.grow.ext_ele_cnt;
                size_t old_sz = (*extern_ele_cnt) * arr->obj.sz;

                base_ref = realloc_safe(base_ref, old_sz, new_sz);
                if (!base_ref) {
                        pr_err("failed to realloc() array [%s] data\n", arr->key);
                        return -ENOMEM;
                }
        }

        arr->obj.arr.grow.alloc_cnt = need_alloc;
        *(uint8_t **)arr->obj.base_ref = base_ref;

        return 0;
}

static int jkey_grow_array_cnt_incr(jkey_t *arr)
{
        size_t *extern_ele_cnt = arr->obj.arr.grow.ext_ele_cnt;

        if (!extern_ele_cnt) {
                pr_err("grow array key [%s] did not define extern element counter\n", arr->key);
                return -EINVAL;
        }

        (*extern_ele_cnt)++;

        return 0;
}

static int jkey_list_array_alloc(jkey_t *arr_key, void **container)
{
        struct list_head *head = arr_key->obj.base_ref;
        struct list_head *node = NULL;
        void *new_ctnr;

        if (!head) {
                pr_err("list array [%s] has NULL list_head\n", arr_key->key);
                return -EINVAL;
        }

        if (!arr_key->obj.arr.list.head_inited) {
                INIT_LIST_HEAD(head);
                arr_key->obj.arr.list.head_inited = 1;
        }

        if (arr_key->obj.sz == 0) {
                pr_err("list array [%s] container size is 0\n", arr_key->key);
                return -EINVAL;
        }

        new_ctnr = calloc(1, arr_key->obj.sz);
        if (!new_ctnr) {
                pr_err("list array [%s] failed to allocate %zu bytes\n", arr_key->key, arr_key->obj.sz);
                return -ENOMEM;
        }

        node = (void *)((uint8_t *)new_ctnr + arr_key->obj.arr.list.offs_head);
        INIT_LIST_HEAD(node);

        list_add_tail(node, head);

        if (container)
                *container = new_ctnr;

        return 0;
}

static int jkey_list_array_ref_update(jkey_t *arr_key, jkey_t *data_key, void *container)
{
        if (data_key->data.ref_parent)
                data_key->data.ref = (uint8_t *)container + arr_key->obj.arr.list.offs_data;

        if (data_key->obj.base_ref_parent)
                data_key->obj.base_ref = (uint8_t *)container + arr_key->obj.arr.list.offs_data;

        return 0;
}

static int jkey_obj_key_ref_update(jkey_t *jkey)
{
        if (jkey->obj.base_ref && jkey->obj.base_ref_ptr)
                jkey->data.ref = *(uint8_t **)jkey->obj.base_ref;

        return 0;
}

static int jkey_child_key_ref_update(jkey_t *parent)
{
        jkey_t *child;

        if (!parent->data.ref)
                return 0;

        for (size_t i = 0; i < parent->child_cnt; i++) {
                child = &((jkey_t *)parent->child)[i];

                if (is_jkey_compound(child)) {
                        if (child->child_cnt)
                                i += child->child_cnt;
                }

                if (child->data.ref_parent)
                        child->data.ref = (uint8_t *)parent->data.ref + child->data.ref_offs;

                if (child->obj.base_ref_parent)
                        child->obj.base_ref = (uint8_t *)parent->data.ref + child->obj.base_ref_offs;
        }

        return 0;
}

static int jkey_child_arr_key_update(jkey_t *parent)
{
        jkey_t *child;

        for (size_t i = 0; i < parent->child_cnt; i++) {
                child = &((jkey_t *)parent->child)[i];

                if (is_jkey_compound(child)) {
                        if (child->child_cnt)
                                i += child->child_cnt;
                }

                if (!is_jkey_writable_array(child))
                        continue;

                if (!child->obj.base_ref_parent)
                        continue;

                switch (child->type) {
                case JKEY_TYPE_GROW_ARRAY:
                {
                        ssize_t ext_ele_cnt_offs = child->obj.arr.grow.ext_ele_cnt_offs;
                        child->obj.arr.grow.ext_ele_cnt = parent->data.ref + ext_ele_cnt_offs;
                        child->obj.arr.grow.alloc_cnt = 0;

                        break;
                }

                case JKEY_TYPE_LIST_ARRAY:
                        child->obj.base_ref = NULL;
                        child->obj.arr.list.head_inited = 0;

                        break;

                }
        }

        return 0;
}

static jkey_t *jkey_child_key_find(jkey_t *parent, cJSON *child_node)
{
        for (size_t i = 0; i < parent->child_cnt; i++) {
                jkey_t *k = &((jkey_t *)parent->child)[i];

                if (is_jkey_cjson_node_match(k, child_node))
                        return k;

                if (is_jkey_compound(k)) {
                        if (k->child_cnt)
                                i += k->child_cnt;
                }
        }

        return NULL;
}

static void cjson_node_print(cJSON *node, uint32_t depth, const size_t *arr_idx)
{
        static const char json_indent[32] = { [0 ... 31] = '\t' };

        // \0 is padded with [] declaration
        if (depth >= (sizeof(json_indent) - 1))
                depth = sizeof(json_indent);

        pr_color(FG_LT_YELLOW, "%.*s", depth, json_indent);

        if (arr_idx)
                pr_color(FG_LT_YELLOW, "[%zu] ", *arr_idx);
        else if (node->string)
                pr_color(FG_LT_YELLOW, "\"%s\" ", node->string);

        switch (node->type) {
        case cJSON_False:
                pr_color(FG_RED, ": false");
                break;
        case cJSON_True:
                pr_color(FG_GREEN, ": true");
                break;
        case cJSON_NULL:
                pr_color(FG_LT_RED, "[null]");
                break;
        case cJSON_Number:
                pr_color(FG_LT_MAGENTA, "[number]");

                double num = cJSON_GetNumberValue(node);

                // does number have fraction part
                if (rint(num) != num)
                        pr_color(FG_LT_CYAN, " : %.2f", num);
                else
                        pr_color(FG_LT_CYAN, " : %.0f", num);

                break;
        case cJSON_String:
                pr_color(FG_LT_GREEN, "[string]");
                pr_color(FG_LT_CYAN, " : \"%s\"", cJSON_GetStringValue(node));
                break;
        case cJSON_Array:
                pr_color(FG_LT_CYAN, "[array]");
                break;
        case cJSON_Object:
                pr_color(FG_LT_BLUE, "[object]");
                break;
        case cJSON_Raw:
                pr_color(FG_LT_RED, "[raws]");
                break;
        }

        pr_color(FG_LT_WHITE, "\n");
}

int jkey_cjson_load_recursive(jkey_t *jkey, cJSON *node, int depth)
{
        cJSON *child_node = NULL;
        int err = 0;


        if (!jkey || !node)
                return 0;

        if (!is_jkey_cjson_node_match(jkey, node))
                return 0;

        if (is_cjson_type(node->type, cJSON_Array)) {
                jkey_t *arr_key = jkey;
                jkey_t *data_key = NULL;
                size_t i = 0;

                if ((err = jkey_array_key_check(arr_key)))
                        return err == -ECANCELED ? 0 : err;

                // always take the first child,
                // since mono-type array is only supported
                data_key = &((jkey_t *)arr_key->child)[0];

                if ((err = jkey_array_data_key_check(arr_key, data_key)))
                        return err;

                cJSON_ArrayForEach(child_node, node) {
                        cjson_node_print(child_node, depth + 1, &i);

                        if (!is_cjson_type(data_key->cjson_type, child_node->type)) {
                                pr_dbg("array [%s] child node #%zu type mismatched, ignored\n", node->string, i);
                                continue;
                        }

                        if ((err = jkey_child_arr_key_update(arr_key)))
                                return err;

                        if (arr_key->type == JKEY_TYPE_FIXED_ARRAY) {
                                if (i >= arr_key->obj.arr.fixed.ele_cnt) {
                                        pr_info("array [%s] input exceeds max element count allocated\n", node->string);
                                        break;
                                }

                                if ((err = jkey_fixed_array_alloc(arr_key)))
                                        return err;

                                if ((err = jkey_fixed_grow_array_ref_update(arr_key, data_key, i)))
                                        return err;
                        } else if (arr_key->type == JKEY_TYPE_GROW_ARRAY) {
                                if ((err = jkey_grow_array_realloc(arr_key, i)))
                                        return err;

                                if ((err = jkey_grow_array_cnt_incr(arr_key)))
                                        return err;

                                if ((err = jkey_fixed_grow_array_ref_update(arr_key, data_key, i)))
                                        return err;
                        } else if (arr_key->type == JKEY_TYPE_LIST_ARRAY) {
                                void *container;

                                if ((err = jkey_list_array_alloc(arr_key, &container)))
                                        return err;

                                jkey_list_array_ref_update(arr_key, data_key, container);
                        }

                        if (is_jkey_compound(data_key)) {
                                if ((err = jkey_cjson_load_recursive(data_key, child_node, depth + 1)))
                                        return err;
                        } else {
                                err = jkey_cjson_input(data_key, child_node);
                                if (err) {
                                        pr_err("failed to parse #%zu item of array [%s]\n", i, node->string);
                                        return err;
                                }
                        }

                        i++;
                }

                return 0;
        }

        if (is_cjson_type(node->type, cJSON_Object)) {
                if ((err = jkey_base_ref_alloc(jkey, jkey->data.sz)))
                        return err;

                if ((err = jkey_obj_key_ref_update(jkey)))
                        return err;

                if ((err = jkey_child_key_ref_update(jkey)))
                        return err;

                if ((err = jkey_child_arr_key_update(jkey)))
                        return err;

                cJSON_ArrayForEach(child_node, node) {
                        jkey_t *child_key = NULL;

                        cjson_node_print(child_node, depth + 1, NULL);

                        //
                        // XXX: O(n^) WARNING!
                        //
                        // is_jkey_cjson_node_match() inside
                        //
                        child_key = jkey_child_key_find(jkey, child_node);
                        if (!child_key) {
                                pr_dbg("child key [%s] is not found in object [%s]\n",
                                       child_node->string, node->string);
                                continue;
                        }

                        if (is_jkey_compound(child_key)) {
                                err = jkey_cjson_load_recursive(child_key, child_node, depth + 1);
                        } else {
                                err = jkey_cjson_input(child_key, child_node);
                        }

                        if (err) {
                                pr_info_once("stack of key on error:\n");
                                cjson_node_print(child_node, depth + 1, NULL);
                                cjson_node_print(node, depth, NULL);

                                return err;
                        }
                }
        }

        return err;
}

int jkey_cjson_load(jkey_t *root_key, cJSON *root_node)
{
        cjson_node_print(root_node, 0, NULL);
        return jkey_cjson_load_recursive(root_key, root_node, 0);
}

int jbuf_load(jbuf_t *buf, const char *json_path)
{
        jkey_t *root_key = jbuf_root_key_get(buf);
        cJSON *root_node;
        char *text;
        int err;

        if (!json_path || json_path[0] == '\0') {
                pr_err("file path is empty\n");
                return -ENODATA;
        }

        text = file_read(json_path);
        if (!text) {
                pr_err("failed to read file: %s\n", json_path);
                return -EIO;
        }

        root_node = cJSON_Parse(text);

        if (!root_node) {
                pr_err("cJSON failed to parse file: %s\n", json_path);
                err = -EINVAL;

                goto text_free;
        }

        err = jkey_cjson_load(root_key, root_node);

        cJSON_Delete(root_node);

text_free:
        free(text);

        return err;
}

int jbuf_traverse_print_pre(jkey_t *jkey, int has_next, int depth)
{
        static char padding[32] = { [0 ... 31] = '\t' };
        (void)has_next;

        printf("%.*s", depth, padding);

        if (jkey->key)
                printf("\"%s\" : ", jkey->key);

        switch (jkey->type) {
        case JKEY_TYPE_OBJECT:
                printf("{\n");
                break;

        case JKEY_TYPE_RO_ARRAY:
        case JKEY_TYPE_FIXED_ARRAY:
        case JKEY_TYPE_GROW_ARRAY:
        case JKEY_TYPE_LIST_ARRAY:
                printf("[\n");
                break;

        default:
                break;
        }

        return 0;
}

int jbuf_traverse_print_post(jkey_t *jkey, int has_next, int depth)
{
        static char padding[32] = { [0 ... 31] = '\t' };
        void *ref = NULL;

        if (is_jkey_compound(jkey)) {
                printf("%.*s", depth, padding);

                switch (jkey->type) {
                case JKEY_TYPE_OBJECT:
                        printf("}");
                        break;

                case JKEY_TYPE_RO_ARRAY:
                case JKEY_TYPE_FIXED_ARRAY:
                case JKEY_TYPE_GROW_ARRAY:
                case JKEY_TYPE_LIST_ARRAY:
                        printf("]");
                        break;
                }

                goto line_ending;
        }

        if (jkey->data.ref) {
                ref = jkey->data.ref;

                if (jkey->data.ref_ptr)
                        ref = *(uint8_t **)jkey->data.ref;
        }

        if (!ref) {
                printf("null");
                goto line_ending;
        }

        switch (jkey->type) {
        case JKEY_TYPE_UINT:
        {
                uint64_t d = 0;

                switch (jkey->data.sz) {
                case sizeof(uint8_t):
                        d = *(uint8_t *)ref;
                        break;
                case sizeof(uint16_t):
                        d = *(uint16_t *)ref;
                        break;
                case sizeof(uint32_t):
                        d = *(uint32_t *)ref;
                        break;

                case sizeof(uint64_t):
                        d = *(uint64_t *)ref;
                        break;

                default:
                        pr_err("does not support for size: %zu\n", jkey->data.sz);
                        break;
                }

                if (jkey->strval.map) {
                        if (d < jkey->strval.cnt)
                                printf("\"%s\"", jkey->strval.map[d]);
                        else
                                printf("null");
                } else if (jkey->data.int_base == 16) {
                        printf("\"0x%016jx\"", d);
                } else {
                        printf("%ju", d);
                }

                break;
        }

        case JKEY_TYPE_INT:
        {
                int64_t d = 0;

                switch (jkey->data.sz) {
                case sizeof(int8_t):
                        d = *(int8_t *)ref;
                        break;
                case sizeof(int16_t):
                        d = *(int16_t *)ref;
                        break;
                case sizeof(int32_t):
                        d = *(int32_t *)ref;
                        break;

                case sizeof(int64_t):
                        d = *(int64_t *)ref;
                        break;

                default:
                        pr_err("does not support for size: %zu\n", jkey->data.sz);
                        break;
                }

                if (jkey->data.int_base == 16)
                        printf("\"0x%016jx\"", d);
                else
                        printf("%jd", d);

                break;
        }

        case JKEY_TYPE_STRREF:
        case JKEY_TYPE_STRPTR:
                printf("\"%s\"", (char *)ref);

                break;

        case JKEY_TYPE_STRBUF:
                printf("\"%.*s\"", (int)jkey->data.sz, (char *)ref);

                break;

        case JKEY_TYPE_BOOL:
                printf("%s", *(jkey_bool_t *)jkey->data.ref ? "true" : "false");

                break;

        case JKEY_TYPE_DOUBLE:
                printf("%.4lf", *(double *)jkey->data.ref);

                break;

        default:
                pr_err("unknown data type: %u\n", jkey->type);
                break;
        }

line_ending:
        if (has_next)
                printf(",");

        printf("\n");
        fflush(stdout);

        return 0;
}

int jbuf_list_array_traverse(jkey_t *arr,
                             int (*pre)(jkey_t *, int, int),
                             int (*post)(jkey_t *, int, int),
                             int depth)
{
        jkey_t *data_key = jkey_array_data_key_get(arr);
        struct list_head *head = arr->obj.base_ref;
        struct list_head *pos, *n;
        int last_one = 0;
        int err = 0;

        if (!head)
                return -ENODATA;

        list_for_each_safe(pos, n, head) {
                void *container;

                if (pos->next == head)
                        last_one = 1;

                container = (uint8_t *)pos - arr->obj.arr.list.offs_head;

                jkey_list_array_ref_update(arr, data_key, container);

                if ((err = jbuf_traverse_recursive(data_key, pre, post, !last_one, depth + 1)))
                        return err;
        }

        return err;
}

int jbuf_fixed_grow_array_traverse(jkey_t *arr,
                                   int (*pre)(jkey_t *, int, int),
                                   int (*post)(jkey_t *, int, int),
                                   int depth)
{
        jkey_t *data_key = jkey_array_data_key_get(arr);
        size_t ele_cnt = 0;
        int last_one = 0;
        int err = 0;

        if (arr->type == JKEY_TYPE_FIXED_ARRAY) {
                ele_cnt = arr->obj.arr.fixed.ele_cnt;
        } else if (arr->type == JKEY_TYPE_GROW_ARRAY) {
                size_t *extern_ele_cnt = arr->obj.arr.grow.ext_ele_cnt;

                if (extern_ele_cnt == NULL)
                        return 0;

                ele_cnt = *extern_ele_cnt;
        }

        for (size_t j = 0; j < ele_cnt; j++) {
                if (j + 1 >= ele_cnt)
                        last_one = 1;

                if (jkey_fixed_grow_array_ref_update(arr, data_key, j))
                        break;

                if ((err = jbuf_traverse_recursive(data_key, pre, post, !last_one, depth + 1)))
                        return err;
        }

        return err;
}

int jbuf_array_traverse(jkey_t *arr,
                        int (*pre)(jkey_t *, int, int),
                        int (*post)(jkey_t *, int, int),
                        int depth)
{
        int err = 0;

        if (arr->type == JKEY_TYPE_LIST_ARRAY) {
                err = jbuf_list_array_traverse(arr, pre, post, depth);
        } else {
                err = jbuf_fixed_grow_array_traverse(arr, pre, post, depth);
        }

        return err;
}

int jbuf_traverse_recursive(jkey_t *jkey,
                            int (*pre)(jkey_t *, int, int),
                            int (*post)(jkey_t *, int, int),
                            int has_next,
                            int depth)
{
        int err = 0;

        if (pre)
                if ((err = pre(jkey, has_next, depth)))
                        return err == -ECANCELED ? 0 : err;

        for (size_t i = 0; i < jkey->child_cnt; i++) {
                jkey_t *child = &(((jkey_t *)jkey->child)[i]);

                if (is_jkey_compound(child)) {
                        if (child->child_cnt)
                                i += child->child_cnt;
                }

                // fixed/grow/list array
                if (is_cjson_type(jkey->cjson_type, cJSON_Array) && jkey->type != JKEY_TYPE_RO_ARRAY) {
                        if ((err = jbuf_array_traverse(jkey, pre, post, depth)))
                                return err;
                } else { // ro array/object/data
                        int last_one = 0;

                        if (i + 1 >= jkey->child_cnt)
                                last_one = 1;

                        if ((err = jkey_child_key_ref_update(jkey)))
                                return err;

                        if ((err = jkey_child_arr_key_update(jkey)))
                                return err;

                        if ((err = jbuf_traverse_recursive(child, pre, post, !last_one, depth + 1)))
                                return err;
                }
        }

        if (post)
                if ((err = post(jkey, has_next, depth)))
                        return err == -ECANCELED ? 0 : err;

        return err;
}

int jbuf_traverse_print(jbuf_t *b)
{
        if (!b)
                return -EINVAL;

        return jbuf_traverse_recursive((void *) b->base,
                                       jbuf_traverse_print_pre, jbuf_traverse_print_post,
                                       0, 0);
}

int jbuf_init(jbuf_t *b, size_t jk_cnt)
{
        if (!b || !jk_cnt)
                return -EINVAL;

        if (b->base || b->head)
                return -EINVAL;

        b->alloc_sz = jk_cnt * sizeof(jkey_t);

        b->base = calloc(1, b->alloc_sz);
        if (!b->base)
                return -ENOMEM;

        b->head = b->base;
        b->end  = (uint8_t *)b->base + b->alloc_sz;

        return 0;
}

int jkey_ref_free(jkey_t *jkey)
{
        void *ref;

        if (!jkey->data.ref)
                return 0;

        if (!jkey->data.ref_ptr || !jkey->data.ref_malloc)
                return 0;

        ref = *(uint8_t **)jkey->data.ref;

        if (!ref) {
//                pr_dbg("key [%s] did not allocated data\n", jkey->key);
                return 0;
        }

        free(ref);
        *(uint8_t **)jkey->data.ref = NULL;

        return 0;
}

int jkey_base_ref_free(jkey_t *jkey)
{
        void *base_ref;

        if (!jkey->obj.base_ref)
                return 0;

        if (!jkey->obj.base_ref_ptr || !jkey->obj.base_ref_malloc)
                return 0;

        base_ref = *(uint8_t **)jkey->obj.base_ref;
        if (!base_ref) {
                pr_dbg("key [%s] did not allocated data\n", jkey->key);
                return 0;
        }

        free(base_ref);
        *(uint8_t **)jkey->obj.base_ref = NULL;

        return 0;
}

int jbuf_traverse_free_pre(jkey_t *jkey, int has_next, int depth)
{
        (void)has_next;
        (void)depth;

        // algorithm is deep-first, free compound object at the last (post cb)
        if (is_jkey_compound(jkey))
                return 0;

        jkey_ref_free(jkey);

        return 0;
}

int jkey_list_array_free(jkey_t *arr)
{
        struct list_head *head = arr->obj.base_ref;
        struct list_head *pos, *n;
        void *container;

        if (!head)
                return -ENODATA;

        list_for_each_safe(pos, n, head) {
                list_del(pos);
                container = (uint8_t *)pos - arr->obj.arr.list.offs_head;
                free(container);
        }

        INIT_LIST_HEAD(head);

        return 0;
}

int jbuf_traverse_free_post(jkey_t *jkey, int has_next, int depth)
{
        (void)has_next;
        (void)depth;

        if (!is_jkey_compound(jkey))
                return 0;

        if (is_cjson_type(jkey->cjson_type, cJSON_Object)) {
                jkey_ref_free(jkey);
                jkey_base_ref_free(jkey);
        } else if (is_cjson_type(jkey->cjson_type, cJSON_Array)) {
                switch (jkey->type) {
                case JKEY_TYPE_GROW_ARRAY:
                case JKEY_TYPE_FIXED_ARRAY:
                        jkey_base_ref_free(jkey);
                        break;

                case JKEY_TYPE_LIST_ARRAY:
                        jkey_list_array_free(jkey);
                        break;
                }
        }

        return 0;
}

int jbuf_traverse_free(jbuf_t *b)
{
        if (!b)
                return -EINVAL;

        return jbuf_traverse_recursive((void *) b->base,
                                       jbuf_traverse_free_pre,
                                       jbuf_traverse_free_post,
                                       0, 0);
}

int jbuf_deinit(jbuf_t *b)
{
        if (!b)
                return -EINVAL;

        if (!b->base)
                return -ENODATA;

        jbuf_traverse_free(b);

        free(b->base);
        memset(b, 0x00, sizeof(jbuf_t));

        return 0;
}
