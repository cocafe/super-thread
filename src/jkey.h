#ifndef __JJ_JKEY_H__
#define __JJ_JKEY_H__

#include <stdint.h>
#include <stdbool.h>

#include "list.h"
#include "cJSON.h"

#define cJSON_Boolean                   (cJSON_False | cJSON_True)
#define cJSON_Compound                  (cJSON_Object | cJSON_Array)

#define JBUF_INIT_ALLOC_KEYS            (20)
#define JBUF_GROW_ARR_REALLOC_INCR      (5)

typedef struct json_key jkey_t;
typedef struct json_key_buf jbuf_t;
typedef uint32_t jkey_bool_t;

enum json_key_types {
        JKEY_TYPE_UNKNOWN = 0,
        JKEY_TYPE_OBJECT,
        JKEY_TYPE_RO_ARRAY,
        JKEY_TYPE_FIXED_ARRAY,
        JKEY_TYPE_GROW_ARRAY,
        JKEY_TYPE_LIST_ARRAY,
        JKEY_TYPE_STRREF,
        JKEY_TYPE_STRBUF,
        JKEY_TYPE_STRPTR,
        JKEY_TYPE_BOOL,
        JKEY_TYPE_INT,
        JKEY_TYPE_UINT,
        JKEY_TYPE_DOUBLE,
        NUM_JKEY_TYPES,
};

struct json_key {
        char                   *key;
        uint32_t                type;
        uint32_t                cjson_type;

        struct {
                size_t          sz;                     // (int, strptr): @data.ref points to data block sz
                // (strbuf): length of static allocated string buffer
                // (strref): this should be 0
                void           *ref;                    // (data, obj): refer to data
                ssize_t         ref_offs;               // offset address of parent's ref
                uint8_t         ref_ptr;                // is @ref pointing to a pointer? (double pointer)
                uint8_t         ref_parent;             // is @ref referencing parent's @data.ref?
                                                        // data_key of array actually refs parent,
                                                        // but this flag is not set for data_key.
                uint8_t         ref_malloc;             // TODO: REMOVE?
                uint8_t         int_base;
                uint8_t         is_wchar;
        } data;

        struct {
                void           *base_ref;               // (arrptr, objptr): base ref address
                ssize_t         base_ref_offs;
                uint8_t         base_ref_ptr;           // is @base_ref pointing to a pointer?
                uint8_t         base_ref_malloc;        // TODO: REMOVE?
                uint8_t         base_ref_parent;        // is @base_ref referencing parent's @data.ref?
                                                        //                                   ^^^^^^^^^
                size_t          sz;
                union {
                        struct {
                                size_t  ele_cnt;
                        } fixed;
                        struct {
                                ssize_t offs_head;
                                ssize_t offs_data;
                                uint8_t head_inited;
                        } list;
                        struct {
                                size_t  alloc_cnt;      // allocated element count
                                size_t *ext_ele_cnt;    // element count for external iteration
                                ssize_t ext_ele_cnt_offs;       // extern counter offset of parent's @data.ref
                        } grow;
                } arr;
        } obj;

        struct {
                char          **map;
                size_t          cnt;
        } strval;

        uint32_t                child_cnt;
        uint8_t                 child[] __attribute__((aligned(8)));
};

struct json_key_buf {
        size_t          alloc_sz;
        void           *base;
        void           *head;
        void           *end;
};

static inline unsigned is_cjson_type(uint32_t a, uint32_t b)
{
        return a & b;
}

int jbuf_load(jbuf_t *buf, const char *json_path);

int jbuf_traverse_print(jbuf_t *b);
int jbuf_traverse_recursive(jkey_t *jkey,
                            int (*pre)(jkey_t *, int, int),
                            int (*post)(jkey_t *, int, int),
                            int has_next,
                            int depth);

int jbuf_init(jbuf_t *b, size_t jk_cnt);
int jbuf_deinit(jbuf_t *b);

jkey_t *jbuf_root_key_get(jbuf_t *b);
jkey_t *jbuf_key_get(jbuf_t *b, void *cookie);
void *jbuf_key_add(jbuf_t *b, int type, char *key, void *ref, size_t sz);

void *jbuf_u8_add(jbuf_t *b, char *key, uint8_t *ref);
void *jbuf_u16_add(jbuf_t *b, char *key, uint16_t *ref);
void *jbuf_u32_add(jbuf_t *b, char *key, uint32_t *ref);
void *jbuf_u64_add(jbuf_t *b, char *key, uint64_t *ref);

void *jbuf_s8_add(jbuf_t *b, char *key, int8_t *ref);
void *jbuf_s16_add(jbuf_t *b, char *key, int16_t *ref);
void *jbuf_s32_add(jbuf_t *b, char *key, int32_t *ref);
void *jbuf_s64_add(jbuf_t *b, char *key, int64_t *ref);

void *jbuf_double_add(jbuf_t *b, char *key, double *ref);
void *jbuf_bool_add(jbuf_t *b, char *key, jkey_bool_t *ref);

void *jbuf_strval_add(jbuf_t *b, char *key, uint32_t *ref, char *map[], size_t map_cnt);
void *jbuf_strptr_add(jbuf_t *b, char *key, char **ref);
void *jbuf_strbuf_add(jbuf_t *b, char *key, char *ref, size_t bytes);
void *jbuf_strref_add(jbuf_t *b, char *key, char *ref);
void *jbuf_wstrptr_add(jbuf_t *b, char *key, wchar_t **ref);
void *jbuf_wstrbuf_add(jbuf_t *b, char *key, wchar_t *ref, size_t bytes);
void *jbuf_wstrref_add(jbuf_t *b, char *key, wchar_t *ref);

void *jbuf_hex_u32_add(jbuf_t *b, char *key, uint32_t *ref);
void *jbuf_hex_u64_add(jbuf_t *b, char *key, uint64_t *ref);

void *jbuf_hex_s32_add(jbuf_t *b, char *key, int32_t *ref);
void *jbuf_hex_s64_add(jbuf_t *b, char *key, int64_t *ref);

#define jbuf_offset_add(buf, type, key, offset)                         \
        do {                                                            \
                void *cookie = jbuf_##type##_add(buf, key, NULL);       \
                if (!cookie)                                            \
                        break;                                          \
                                                                        \
                jkey_ref_parent_set(buf, cookie, offset);               \
        } while (0)

#define jbuf_offset_obj_open(buf, cookie, key, offset)                  \
        do {                                                            \
                void *t = jbuf_obj_open(buf, key);                      \
                if (!t) {                                               \
                        cookie = NULL;                                  \
                        break;                                          \
                }                                                       \
                                                                        \
                jkey_ref_parent_set(buf, t, offset);                    \
                cookie = t;                                             \
        } while (0)

#define jbuf_array_data_key(buf, type) jbuf_offset_add(buf, type, NULL, 0)
#define jbuf_array_obj_data_key(buf, cookie) jbuf_offset_obj_open(buf, cookie, NULL, 0)

void *jbuf_offset_strbuf_add(jbuf_t *b, char *key, ssize_t offset, size_t len);
void *jbuf_offset_wstrbuf_add(jbuf_t *b, char *key, ssize_t offset, size_t len);
void *jbuf_offset_strval_add(jbuf_t *b, char *key, ssize_t offset, char *map[], size_t map_cnt);

void jkey_ref_parent_set(jbuf_t *b, void *cookie, ssize_t offset);
void jkey_base_ref_parent_set(jbuf_t *b, void *cookie, ssize_t offset);
void jkey_int_base_set(jbuf_t *b, void *cookie, uint8_t int_base);

void *jbuf_obj_open(jbuf_t *b, char *key);
void *jbuf_objptr_open(jbuf_t *b, char *key, void *ref, size_t sz);
void jbuf_obj_close(jbuf_t *b, void *cookie);

void *jbuf_arr_open(jbuf_t *b, char *key);
void jbuf_arr_close(jbuf_t *b, void *cookie);

void *jbuf_fixed_arr_open(jbuf_t *b, char *key);
void jbuf_fixed_arr_setup(jbuf_t *b, void *cookie, void *ref, size_t ele_cnt, size_t ele_sz);
void jbuf_fixed_arrptr_setup(jbuf_t *b, void *cookie, void **ref, size_t ele_cnt, size_t ele_sz);
void jbuf_offset_fixed_arr_setup(jbuf_t *b, void *cookie, ssize_t offset, size_t ele_cnt, size_t ele_sz);

void *jbuf_grow_arr_open(jbuf_t *b, char *key);
void jbuf_grow_arr_setup(jbuf_t *b, void *cookie, void **ref, size_t *ext_ele_cnt, size_t ele_sz);
void jbuf_offset_grow_arr_setup(jbuf_t *b, void *cookie, ssize_t offset, ssize_t ext_ele_cnt_offs, size_t ele_sz);

void *jbuf_list_arr_open(jbuf_t *b, char *key);
void jbuf_list_arr_setup(jbuf_t *b, void *cookie,
                         struct list_head *head,
                         size_t ctnr_sz,
                         ssize_t offsof_ctnr_head,
                         size_t ctnr_data_sz,
                         ssize_t offsof_ctnr_data);
void jbuf_offset_list_arr_setup(jbuf_t *b,
                                void *cookie,
                                ssize_t offsof_head_in_parent,
                                size_t ctnr_sz,
                                ssize_t offsof_ctnr_head,
                                size_t ctnr_data_sz,
                                ssize_t offsof_ctnr_data);

#endif /* __JJ_JKEY_H__ */