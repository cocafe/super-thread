#ifndef __JJ_JKEY_H__
#define __JJ_JKEY_H__

#include <stdint.h>
#include <stdbool.h>

#include "list.h"
#include "cJSON.h"

#define cJSON_Boolean           (cJSON_False | cJSON_True)
#define cJSON_Compound          (cJSON_Object | cJSON_Array)

typedef struct json_key jkey_t;
typedef struct json_key_buf jbuf_t;
typedef uint32_t jkey_bool_t;

enum json_key_types {
        JKEY_TYPE_UNKNOWN = 0,
        JKEY_TYPE_OBJECT,
        JKEY_TYPE_ARRAY,
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
                ssize_t         offset;         // offset address of parent's ref
                void           *ref;            // (data, obj): refer to data
                size_t          sz;             // (int, strptr): @data.ref points to data block sz
                                                // (strbuf): length of static allocated string buffer
                                                // (strref): this should be 0
                uint8_t         int_base;
                uint8_t         ref_ptr;        // is @ref pointing to a pointer? (double pointer)
                uint8_t         ref_parent;     // is this key referencing parent's ref?
                uint8_t         ref_malloc;     // TODO: REMOVE?
        } data;

        struct {
                void           *base_ref;       // (arrptr, objptr): base ref address
                uint8_t         base_ref_ptr;   // is @base_ref pointing to a pointer?
                uint8_t         base_ref_malloc;// TODO: REMOVE?
                uint8_t         is_arr;
                size_t          ele_sz;
                size_t          arr_cnt;        // array element cnt
                ssize_t         list_head_offs;
                ssize_t         data_ref_offs;
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

int json_load(jkey_t *root_key, const char *path);
int jbuf_traverse_print(jbuf_t *b);

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

void *jbuf_hex_u32_add(jbuf_t *b, char *key, uint32_t *ref);
void *jbuf_hex_u64_add(jbuf_t *b, char *key, uint64_t *ref);

void *jbuf_hex_s32_add(jbuf_t *b, char *key, int32_t *ref);
void *jbuf_hex_s64_add(jbuf_t *b, char *key, int64_t *ref);

void *jbuf_offset_u32_add(jbuf_t *b, char *key, ssize_t offset);
void *jbuf_offset_s32_add(jbuf_t *b, char *key, ssize_t offset);
void *jbuf_offset_strbuf_add(jbuf_t *b, char *key, ssize_t offset, size_t len);
void *jbuf_offset_strptr_add(jbuf_t *b, char *key, ssize_t offset);

void *jbuf_strval_add(jbuf_t *b, char *key, uint32_t *ref, char **map, size_t map_cnt);
void *jbuf_strptr_add(jbuf_t *b, char *key, char **ref);
void *jbuf_strbuf_add(jbuf_t *b, char *key, char *ref, size_t len);
void *jbuf_strref_add(jbuf_t *b, char *key, char *ref);

void *jbuf_obj_open(jbuf_t *b, char *key);
void *jbuf_objptr_open(jbuf_t *b, char *key, void *ref, size_t sz);
void jbuf_obj_close(jbuf_t *b, void *cookie);

void *jbuf_arr_open(jbuf_t *b, char *key);
void jbuf_arr_close(jbuf_t *b, void *cookie);

void *jbuf_static_arr_open(jbuf_t *b, char *key);
void *jbuf_fixed_arr_desc(jbuf_t *b, int jkey_type, void *ref, size_t arr_cnt, size_t ele_sz);
void *jbuf_fixed_arrptr_desc(jbuf_t *b, int jkey_type, void *ref, size_t arr_cnt, size_t ele_sz);
void *jbuf_fixed_array_strptr_desc(jbuf_t *b, void *ref, size_t arr_sz, size_t ele_sz);

void *jbuf_grow_arr_open(jbuf_t *b, char *key);
void *jbuf_grow_arr_desc(jbuf_t *b, int jkey_type, void *ref, size_t ele_sz);
void *jbuf_strptr_grow_arr_desc(jbuf_t *b, void *ref, size_t ele_sz);

void *jbuf_list_arr_open(jbuf_t *b, char *key);
void *jbuf_list_arr_desc(jbuf_t *b,
                         int jkey_type,
                         struct list_head *head,
                         size_t container_sz,
                         ssize_t offsetof_head,
                         size_t data_sz,
                         ssize_t offsetof_data);

int jbuf_traverse_recursive(jkey_t *jkey,
                            int (*pre)(jkey_t *, int, int),
                            int (*post)(jkey_t *, int, int),
                            int has_next,
                            int depth);

#endif /* __JJ_JKEY_H__ */