#ifndef VOIP_PHONE_CONFIG_JSON_H
#define VOIP_PHONE_CONFIG_JSON_H

#include "utils.h"

#include "config_opt.h"

/**
 * Note:
 *      json array:
 *          1. need to keep C structure layout same as the json layout.
 *          2. any kind of sub keys of array key should refer parents @data_ref,
 *             aka, sub key should define @data_ref_uplvl and @data_offset
 *          3. parent array key should define @arr_ref, @ele_sz and @ele_cnt
 *          4. simple array that does not contain any compound node (object, array)
 *             and only wants mono data type, should define a NAMELESS child,
 *             @key = NULL, and @data_offset = 0 to receive array data
 *          5. complex array with nested nameless array or with mixed type data
 *             is not supported yet, e.g.
 *                  "test": [ [ "123", 123 ], { "jiji":true }, [ ... ] ]
 */

struct json_key {
        char           *key;

        uint32_t        cjson_type;     // cjson type of node to match
        cJSON          *cjson_node;

        size_t          ele_sz;
        size_t          ele_cnt;

        void           *base_ref;       // base address of array or
        // object with (@data_ref_ptr == true).
        // need to update actual address @data_ref.
        // while updating sub keys which refer
        // parents, will update their @base_ref.

        void           *data_ref;       // object/array: address currently on
        // other: address of data to store

        void           *data_init;      // if not NULL, set as default value.
        // require @data_sz defined.
        // currently only works for compound data,
        // as atomic data will be always written.
        size_t          data_sz;
        ssize_t         data_offset;    // use with @data_ref_uplvl

        uint8_t         data_type;
        uint8_t         data_malloc;    // use with @data_ref_ptr

        uint8_t         data_ref_ptr;   // use with @data_ref:
        // is @data_ref points to a pointer?
        // aka, @data_ref is a double pointer?

        uint8_t         data_ref_uplvl; // use with @data_offset
        // is @data_ref should refer parent's
        // @data_ref? mandatory when wrapped by
        // array parent key

        const optstr_t *optstrs;        // array to convert string to enum value

        uint8_t         set_zero;       // memset() zero when init the key
        // use with @data_sz attribute

        uint8_t         int_base;       // use to convert between number and string
        // aka. workaround for converting hex
        // string to number, vice versa

        uint8_t         have_child;     // flag to determine flexible
        // array @child is defined or not

        json_key_t     *child[];        // list of children key pointers
        // MUST be NULL terminated
};

/**
 * NOTE:
 *
 * jk_strptr: string pointer to string pointer which may point to NULL and need alloc
 * jk_strref: string pointer to string pointer which also may be NULL and size unknown, no alloc
 * jk_strbuf: string pointer to static buffer which size need to be knew
 *
 * use (jk_.*_m) macros with caution, @container may need to guarded with brackets outside
 */

#define jk_strptr_offset(name, offset)  \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_String, \
        .data_type      = D_STRING,     \
        .data_ref       = NULL,         \
        .data_ref_ptr   = 1,            \
        .data_malloc    = 1,            \
        .data_ref_uplvl = 1,            \
        .data_offset    = (offset),     \
        .data_sz        = 0,            \
        .optstrs        = NULL,         \
}

#define jk_strref_offset(name, offset)  \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_String, \
        .data_type      = D_STRING,     \
        .data_ref       = NULL,         \
        .data_ref_ptr   = 1,            \
        .data_ref_uplvl = 1,            \
        .data_offset    = (offset),     \
        .data_sz        = 0,            \
        .optstrs        = NULL,         \
}

#define jk_strbuf_offset(name, size, offset) \
&(json_key_t) {                              \
        .key            = (name),            \
        .cjson_type     = cJSON_String,      \
        .data_type      = D_STRING,          \
        .data_ref       = NULL,              \
        .data_ref_uplvl = 1,                 \
        .data_offset    = (offset),          \
        .data_sz        = size,              \
        .optstrs        = NULL,              \
}

#define jk_int_offset(name, size, offset)       \
&(json_key_t) {                                 \
        .key            = (name),               \
        .cjson_type     = cJSON_Number,         \
        .data_type      = D_SIGNED,             \
        .data_ref       = NULL,                 \
        .data_ref_uplvl = 1,                    \
        .data_offset    = (offset),             \
        .data_sz        = (size),               \
        .optstrs        = NULL,                 \
}

#define jk_uint_offset(name, size, offset)      \
&(json_key_t) {                                 \
        .key            = (name),               \
        .cjson_type     = cJSON_Number,         \
        .data_type      = D_UNSIGNED,           \
        .data_ref       = NULL,                 \
        .data_ref_uplvl = 1,                    \
        .data_offset    = (offset),             \
        .data_sz        = (size),               \
        .optstrs        = NULL,                 \
}

#define jk_bool_offset(name, size, offset)      \
&(json_key_t) {                                 \
        .key            = (name),               \
        .cjson_type     = cJSON_Boolean,        \
        .data_type      = D_BOOLEAN,            \
        .data_ref       = NULL,                 \
        .data_ref_uplvl = 1,                    \
        .data_offset    = (offset),             \
        .data_sz        = (size),               \
        .optstrs        = NULL,                 \
}

#define jk_optstr_offset(name, size, offset, optstr)    \
&(json_key_t) {                                         \
        .key            = (name),                       \
        .cjson_type     = cJSON_String,                 \
        .data_type      = D_UNSIGNED,                   \
        .data_ref       = NULL,                         \
        .data_ref_uplvl = 1,                            \
        .data_offset    = (offset),                     \
        .data_sz        = (size),                       \
        .optstrs        = optstr,                       \
}

#define jk_strptr(name, ref)            \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_String, \
        .data_type      = D_STRING,     \
        .data_ref       = (ref),        \
        .data_ref_ptr   = 1,            \
        .data_malloc    = 1,            \
        .data_sz        = 0,            \
}

/* reference only, no @data_malloc */
#define jk_strref(name, ref)            \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_String, \
        .data_type      = D_STRING,     \
        .data_ref       = (ref),        \
        .data_ref_ptr   = 1,            \
        .data_sz        = 0,            \
}

#define jk_strbuf(name, size, ref)      \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_String, \
        .data_type      = D_STRING,     \
        .data_ref       = (ref),        \
        .data_sz        = (size),       \
}

#define jk_int(name, size, ref)         \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_Number, \
        .data_type      = D_SIGNED,     \
        .data_ref       = (ref),        \
        .data_sz        = (size),       \
}

#define jk_uint(name, size, ref)        \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_Number, \
        .data_type      = D_UNSIGNED,   \
        .data_ref       = (ref),        \
        .data_sz        = (size),       \
}

#define jk_strint(name, size, ref, base) \
&(json_key_t) {                          \
        .key            = (name),        \
        .cjson_type     = cJSON_String,  \
        .data_type      = D_SIGNED,      \
        .data_ref       = (ref),         \
        .data_sz        = (size),        \
        .int_base       = (base),        \
}

#define jk_struint(name, size, ref, base) \
&(json_key_t) {                           \
        .key            = (name),         \
        .cjson_type     = cJSON_String,   \
        .data_type      = D_UNSIGNED,     \
        .data_ref       = (ref),          \
        .data_sz        = (size),         \
        .int_base       = (base),         \
}

#define jk_flt(name, size, ref)         \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_Number, \
        .data_type      = D_FLOAT,      \
        .data_ref       = (ref),        \
        .data_sz        = (size),       \
}

#define jk_dbl(name, size, ref)         \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_Number, \
        .data_type      = D_DOUBLE,     \
        .data_ref       = (ref),        \
        .data_sz        = (size),       \
}

#define jk_bool(name, size, ref)        \
&(json_key_t) {                         \
        .key            = (name),       \
        .cjson_type     = cJSON_Boolean,\
        .data_type      = D_BOOLEAN,    \
        .data_ref       = (ref),        \
        .data_sz        = (size),       \
}

#define jk_optstr(name, size, ref, optstr)      \
&(json_key_t) {                                 \
        .key            = (name),               \
        .cjson_type     = cJSON_String,         \
        .data_type      = D_UNSIGNED,           \
        .data_ref       = (ref),                \
        .data_sz        = (size),               \
        .optstrs        = (optstr),             \
}

#define jk_strptr_offset_m(name, container, member)             \
        jk_strptr_offset(name, (offsetof(typeof(container), member)))

#define jk_strref_offset_m(name, container, member)             \
        jk_strref_offset(name, (offsetof(typeof(container), member))) \

#define jk_strbuf_offset_m(name, container, member)             \
        jk_strbuf_offset(name,                                  \
                         (sizeof(container.member)),            \
                         (offsetof(typeof(container), member)))

#define jk_optstr_offset_m(name, container, member, optstr)     \
        jk_optstr_offset(name,                                  \
                         (sizeof(container.member)),            \
                         (offsetof(typeof(container), member)), \
                         optstr)

#define jk_int_offset_m(name, container, member)                \
        jk_int_offset(name,                                     \
                       (sizeof(container.member)),              \
                       (offsetof(typeof(container), member)))

#define jk_uint_offset_m(name, container, member)               \
        jk_uint_offset(name,                                    \
                       (sizeof(container.member)),              \
                       (offsetof(typeof(container), member)))

#define jk_bool_offset_m(name, container, member)               \
        jk_bool_offset(name,                                    \
                       (sizeof(container.member)),              \
                       (offsetof(typeof(container), member)))

//
// be careful with '&object' below
//

#define jk_strref_o(name, object)                               \
        jk_strref(name, object)

#define jk_strbuf_o(name, object)                               \
        jk_strbuf(name, sizeof(object), object)

#define jk_optstr_o(name, object, optstr)                       \
        jk_optstr(name, sizeof(object), &object, optstr)

#define jk_int_o(name, object)                                  \
        jk_int(name, sizeof(object), &object)

#define jk_uint_o(name, object)                                 \
        jk_uint(name, sizeof(object), &object)

#define jk_bin_o(name, object)                                  \
        jk_strint(name, sizeof(object), &object, 2)

#define jk_ubin_o(name, object)                                 \
        jk_struint(name, sizeof(object), &object, 2)

#define jk_octa_o(name, object)                                  \
        jk_strint(name, sizeof(object), &object, 8)

#define jk_uocta_o(name, object)                                 \
        jk_struint(name, sizeof(object), &object, 8)

#define jk_hex_o(name, object)                                  \
        jk_strint(name, sizeof(object), &object, 16)

#define jk_uhex_o(name, object)                                 \
        jk_struint(name, sizeof(object), &object, 16)

#define jk_bool_o(name, object)                                 \
        jk_bool(name, sizeof(object), &object)

#define jk_flt_o(name, object)                                  \
        jk_flt(name, sizeof(object), &object)

#define jk_dbl_o(name, object)                                  \
        jk_dbl(name, sizeof(object), &object)

extern json_key_t jkey_root_usrcfg;
extern json_key_t jkey_root_sip_stats;
extern json_key_t jkey_root_call_stats;

typedef int (*jkey_traverse_cb)(json_key_t *curr, json_key_t *parent, void *priv);

json_key_t *json_key_alloc(size_t child_cnt);
json_key_t *json_key_clone(json_key_t *src);

int json_load(json_key_t *root_key, const char *path);
int json_save(json_key_t *root_key, const char *path, int formatted);
int json_decode(json_key_t *root_key, const char *text);
int json_encode(json_key_t *root_key, char **text, int formatted);
void json_key_printf(json_key_t *root_key);
int json_key_to_node(json_key_t *root_key, cJSON **root_node);
int json_key_val_load(cJSON *root_node, json_key_t *root_key);
int json_key_recursive_free(json_key_t *root_key);
int json_key_traverse(json_key_t *curr, json_key_t *parent, void *data,
                      jkey_traverse_cb pre_cb, jkey_traverse_cb post_cb);

#endif // VOIP_PHONE_CONFIG_JSON_H
