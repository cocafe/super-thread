#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include "voip_phone.h"
#include "config_opt.h"
#include "config_json.h"
#include "utils.h"
#include "logging.h"

#include "cJSON.h"

json_key_t *json_key_alloc(size_t child_cnt)
{
        json_key_t *key;

        // for NULL terminated
        if (child_cnt)
                child_cnt += 1;

        key = calloc(1, sizeof(json_key_t) + sizeof(json_key_t *) * (child_cnt + 1));
        if (!key)
                return NULL;

        if (child_cnt) {
                key->have_child = 1;
                key->child[child_cnt] = NULL;
        }

        return key;
}

json_key_t *json_key_clone(json_key_t *src)
{
        json_key_t *n;
        size_t sz = sizeof(json_key_t);

        if (!src)
                return NULL;

        if (src->have_child) {
                int i = 0;
                json_key_t *c = src->child[0];

                // for NULL terminated
                sz += sizeof(json_key_t *);

                while (c) {
                        sz += sizeof(json_key_t *);
                        c = src->child[++i];
                }
        }

        n = calloc(1, sz);
        if (!n) {
                // properly child list not ended with NULL
                pr_err("failed to allocate %d bytes\n", sz);
                return NULL;
        }

        memcpy(n, src, sz);

        return n;
}

void json_key_printf(json_key_t *root_key)
{
        char *text = NULL;

        if (json_encode(root_key, &text, 1)) {
                pr_err("json_encode() failed\n");
                goto out;
        }

        printf("%s\n", text);

out:
        if (text)
                free(text);
}

static inline void dbl_ptr_deref(json_key_t *k, void **res)
{
        *res = NULL;

        if (!k->data_ref_ptr)
                return;

        if (k->data_ref && *(uint8_t **)k->data_ref)
                *res = *(uint8_t **)k->data_ref;
}

static inline int dbl_ptr_calloc(json_key_t *k, size_t sz, void **res)
{
        *res = NULL;

        // XXX: verbose check
        if (!k->data_ref)
                return -EINVAL;

        if (!k->data_ref_ptr || !k->data_malloc)
                return 0;

        if (*(uint8_t **)k->data_ref)
                pr_warn("dereferenced key [%s] is not NULL!\n", k->key);

        *(uint8_t **)k->data_ref = calloc(1, sz);
        if (*(uint8_t **)k->data_ref == NULL) {
                pr_err("failed to allocate memory\n");
                return -ENOMEM;
        }

        *res = *(uint8_t **)k->data_ref;

        return 0;
}


static int json_str_dump(cJSON *n, struct json_key *k)
{
        char *json_str = cJSON_GetStringValue(n);
        size_t json_len, copy_len;
        void *dst = NULL;

        if (!json_str) {
                pr_err("failed to read string from key [%s]\n", n->string);
                return -ENODATA;
        }

        json_len = strlen(json_str);

        if (json_str[0] == '\0') {
//                pr_dbg("json key [%s] has empty string, skip\n", n->string);
                return 0;
        }

        // convert a string to a number?
        if (k->data_type & D_INTEGER) {
                if (k->int_base) {
                        long long t = strtoll(json_str, NULL, k->int_base);
                        return ptr_word_write(k->data_ref, k->data_sz, t);
                }

                // convert string to a enum value
                if (k->optstrs) {
                        return optstr_to_int(k->data_ref, json_str,
                                             2, k->data_sz, k->optstrs);
                }
        }

        // check whether double pointer and malloc its memory
        dbl_ptr_deref(k, &dst);
        if (!dst) {
                if (dbl_ptr_calloc(k, json_len + 2, &dst))
                        return -ENOMEM;
        }

        // if @k->data_ref is not double pointer
        if (!dst)
                dst = k->data_ref;

        // must check != 0
        if (!k->data_sz) {
                copy_len = json_len;
        } else {
                copy_len = __min(json_len, k->data_sz);
        }

        strncpy(dst, json_str, copy_len);

        // set null terminated?

        return 0;
}

static int json_bool_dump(cJSON *n, json_key_t *k)
{
        uint32_t val = (n->type == cJSON_True) ? D_BOOL_TRUE : D_BOOL_FALSE;
        void *dst = NULL;

        /**
         * @k->data_ref != NULL checked outside
         */

        if (k->data_sz == 0) {
                pr_err("@data_sz for key [%s] is 0\n", n->string);
                return -EFAULT;
        }

        dbl_ptr_deref(k, &dst);
        if (!dst) {
                if (dbl_ptr_calloc(k, k->data_sz, &dst))
                        return -ENOMEM;
        }

        // if @k->data_ref is not double pointer
        if (!dst)
                dst = k->data_ref;

        ptr_word_write(dst, k->data_sz, val);

        return 0;
}

static int json_int_dump(cJSON *n, json_key_t *k)
{
        double dbl = cJSON_GetNumberValue(n);
        void *dst = NULL;

        if (isnan(dbl)) {
                pr_err("failed to get number for cJSON\n");
                return -ENODATA;
        }

        if (k->data_sz == 0) {
                pr_err("@data_sz for key [%s] is 0\n", n->string);
                return -EFAULT;
        }

        dbl_ptr_deref(k, &dst);
        if (!dst) {
                if (dbl_ptr_calloc(k, k->data_sz, &dst))
                        return -ENOMEM;
        }

        // if @k->data_ref is not double pointer
        if (!dst)
                dst = k->data_ref;

        ptr_word_write(dst, k->data_sz, (int64_t)dbl);

        return 0;
}

static int json_flt_dump(cJSON *n, json_key_t *k)
{
        double dbl = cJSON_GetNumberValue(n);
        void *dst = NULL;

        if (isnan(dbl)) {
                pr_err("failed to get number for cJSON\n");
                return -ENODATA;
        }

        if (k->data_sz == 0) {
                pr_err("@data_sz for key [%s] is 0\n", n->string);
                return -EFAULT;
        }

        dbl_ptr_deref(k, &dst);
        if (!dst) {
                if (dbl_ptr_calloc(k, k->data_sz, &dst))
                        return -ENOMEM;
        }

        // if @k->data_ref is not double pointer
        if (!dst)
                dst = k->data_ref;

        if (k->data_type == D_FLOAT) {
                if (unlikely(k->data_sz != sizeof(float)))
                        pr_warn("@data_sz of key [%s] mismatched float size\n", k->key);

#ifdef __ARM_ARCH_7A__
                // unaligned access on float type will cause SIGBUS on armhf
                if (likely((size_t)dst % sizeof(float) == 0)) {
                        *(float *)dst = (float)dbl;
                } else {
                        pr_warn("float point unaligned access detected, fix your struct\n");
                        memcpy(dst, &(float) {(float) dbl}, sizeof(float));
                }
#else
                *(float *)dst = (float)dbl;
#endif
        } else if (k->data_type == D_DOUBLE) {
                if (unlikely(k->data_sz != sizeof(double)))
                        pr_warn("@data_sz of key [%s] mismatched double size\n", k->key);

                *(double *) dst = dbl;
        } else {
                return -EFAULT;
        }

        return 0;
}

int json_value_dump(cJSON *n, json_key_t *k, json_key_t *parent)
{
        int err;

        if (!k || !n)
                return -EINVAL;

        if (k->data_ref_uplvl) { // offset set below
                if (!parent) {
                        pr_err("@parent is not passed while @data_ref_uplvl == 1\n");
                        return -EFAULT;
                }

                if (!parent->data_ref) {
                        pr_err("@data_ref of parent key [%s] is NULL\n", parent->key);
                        return -ENODATA;
                }

                // if parent key is array, this @data_ref has been calc once.
                // but with object parent key will not be calc previous at outside
                k->data_ref = parent->data_ref;
                k->data_ref = (uint8_t *)k->data_ref + k->data_offset;
        } else if (!k->data_ref) {
                pr_err("@data_ref of key [%s] is NULL\n", k->key);
                return -EINVAL;
        }

        if (!is_cjson_type(n->type, k->cjson_type)) {
                pr_err("json key [%s] has mismatched cjson data type\n", k->key);
                return -EINVAL;
        }

        // test cjson type of node
        switch (n->type) {
        case cJSON_True:
        case cJSON_False:
                err = json_bool_dump(n, k);
                break;

        case cJSON_String:
                err = json_str_dump(n, k);
                break;

        case cJSON_Number:
                switch (k->data_type) {
                case D_INTEGER:
                case D_SIGNED:
                case D_UNSIGNED:
                        err = json_int_dump(n, k);
                        break;

                case D_FLOAT:
                case D_DOUBLE:
                        err = json_flt_dump(n, k);
                        break;

                default:
                        err = -EFAULT;
                        break;
                }

                break;

        case cJSON_NULL:
        case cJSON_Array:
        case cJSON_Object:
        default:
                pr_warn("unhandled cjson type 0x%0x\n", k->cjson_type);
                err = -EFAULT;
                break;
        }

        if (err && k->data_ref_ptr) {
                void *d = k->data_ref;
                if (d && *(uint8_t **)d) {
                        free(*(uint8_t **)d);
                        *(uint8_t **)d = NULL;
                }
        }

        return err;
}

void json_node_print(cJSON *n, uint32_t depth, const size_t *arr_idx)
{
        static const char json_indent[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

        // \0 is padded with [] declaration
        if (depth >= (sizeof(json_indent) - 1)) {
                pr_dbg("maximum depth is reached\n");
                depth = sizeof(json_indent);
        }

        pr_color(FG_LT_YELLOW, "%.*s", depth, json_indent);

        if (arr_idx)
                pr_color(FG_LT_YELLOW, "[%zu] ", *arr_idx);
        else
                pr_color(FG_LT_YELLOW, "[%s] ", n->string);

        switch (n->type) {
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

                double num = cJSON_GetNumberValue(n);

                // does number have fraction part
                if (rint(num) != num)
                        pr_color(FG_LT_CYAN, " : %.2f", num);
                else
                        pr_color(FG_LT_CYAN, " : %.0f", num);

                break;
        case cJSON_String:
                pr_color(FG_LT_GREEN, "[string]");
                pr_color(FG_LT_CYAN, " : \"%s\"", cJSON_GetStringValue(n));
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

static inline json_key_t *json_sub_key_get(json_key_t *parent, char *key)
{
        json_key_t *k;
        size_t i;

        if (!parent || !key)
                return NULL;

        if (!parent->have_child)
                return NULL;

        for (i = 0, k = parent->child[i]; k != NULL; k = parent->child[++i]) {
                if (!k->key) {
                        pr_err("#%zu child of key [%s] does not have name defined\n",
                               i, parent->key);
                        continue;
                }

                if (!__str_cmp(k->key, key, 0))
                        return k;
        }

        return NULL;
}

/**
 * json_obj_key_update() - update object
 * @param k: current json key
 * @param do_malloc: use on loading json content
 * @return 0 on success
 */
static int json_obj_key_update(json_key_t *k, int do_malloc)
{
        // (k->cjson_type == cJSON_Object) checked assumed

        if (!k->base_ref || !k->data_ref_ptr)
                return 0;

        k->data_ref = NULL;

        // abort on referencing NULL pointer
        if (*(uint8_t **)k->base_ref == NULL) {
                if (do_malloc) {
                        if (!k->data_malloc) {
                                pr_warn("key [%s] to allocate but @data_malloc is not set\n", k->key);
                                return -ECANCELED;
                        }

                        if (!k->data_sz) {
                                pr_err("key [%s] to allocate but @data_sz is not set\n", k->key);
                                return -EINVAL;
                        }

                        void *alloc = calloc(1, k->data_sz);
                        if (!alloc) {
                                pr_err("key [%s] failed to allocate size %zu\n", k->key, k->data_sz);
                                return -ENOMEM;
                        }

                        *(uint8_t **)k->base_ref = alloc;
                }

                return -ECANCELED;
        } else if (do_malloc) {
                pr_dbg("key [%s] refs uncleaned ptr\n", k->key);
        }

        k->data_ref = *(uint8_t **)k->base_ref;

        return 0;
}

static int json_key_data_init(json_key_t *k)
{
        if (!k->data_init && !k->set_zero)
                return 0;

        if (!k->data_sz) {
                pr_warn("key [%s]: @data_init defined without @data_sz\n", k->key);
                return -EINVAL;
        }

        if (!k->data_ref) {
                pr_warn("key [%s]: @data_ref is NULL\n", k->key);
                return -ENODATA;
        }

        if (k->data_init)
                memcpy(k->data_ref, k->data_init, k->data_sz);
        else // set_zero
                memset(k->data_ref, 0, k->data_sz);

        return 0;
}

/**
 * json_array_key_update() - update array info in array iteration
 * @param k: array key
 * @param idx: current index
 * @param do_deref: de-reference and update @data_ref if @k->data_ref_ptr
 * @param do_malloc: allocate data memory on (@data_ref == NULL && @data_malloc)
 * @return 0 on success
 */
static int json_array_key_update(json_key_t *k, size_t idx,
                                 int do_deref, int do_malloc)
{
        void *ele_ref = (uint8_t *)k->base_ref + k->ele_sz * idx;

        k->data_ref = ele_ref;

        if (!k->data_ref_ptr) {
                return 0;
        }

        if (!ele_ref) {
                pr_err("key %s: @data_ref_ptr and @ele_ref is NULL\n", k->key);
                return -ENODATA;
        }

        if (do_malloc) {
                if (*(uint8_t **)ele_ref == NULL) {
                        if (!k->data_malloc) {
                                pr_err("key [%s] ref ptr but NULL and"
                                       "@data_malloc is not set\n", k->key);
                                return -EINVAL;
                        }

                        if (!k->data_sz) {
                                pr_err("deref @data_ref is empty, @data_sz of "
                                       "key [%s] is not defined\n", k->key);
                                return -EINVAL;
                        }

                        void *alloc = calloc(1, k->data_sz);
                        if (!alloc) {
                                pr_err("failed to allocate memory for "
                                       "#%zu of array [%s]\n", idx, k->key);
                                return -ENOMEM;
                        }

                        *(uint8_t **)ele_ref = alloc;
                } else {
                        pr_dbg("key [%s] refs uncleaned ptr\n", k->key);
                }
        }

        if (do_deref)
                k->data_ref = *(uint8_t **)ele_ref;

        return 0;
}

int json_sub_keys_update(json_key_t *parent)
{
        uint8_t *base = parent->data_ref;
        json_key_t *sub;
        size_t i;

        if (parent->data_ref == NULL)
                return 0;

        for (i = 0, sub = parent->child[i]; sub != NULL; sub = parent->child[++i]) {
                if (!sub->data_ref_uplvl) {
                        if (parent->cjson_type == cJSON_Array) {
                                pr_err("all sub key [%s] of array key should "
                                       "refer their parent address\n", sub->key);
                                return -EINVAL;
                        }

                        continue;
                }

                if (sub->cjson_type == cJSON_Array) {
                        // @arr_ref is required while iterating array
                        sub->base_ref = base + sub->data_offset;
                } else { // other types
                        if (sub->cjson_type == cJSON_Object &&
                            sub->data_ref_ptr) {
                                sub->base_ref = base + sub->data_offset;
                                continue;
                        }

                        sub->data_ref = base + sub->data_offset;
                }
        }

        return 0;
}

static inline int json_array_key_check(json_key_t *k)
{
        if (!k->base_ref) {
                pr_err("@arr_ref of json key [%s] is not set\n", k->key);
                return -EINVAL;
        }

        if (k->ele_sz == 0) {
                pr_err("@ele_sz of array json key [%s] is zero\n", k->key);
                return -EINVAL;
        }

        if (k->ele_cnt == 0) {
                pr_err("@ele_cnt of array json key [%s] is zero\n", k->key);
                return -EINVAL;
        }

        if (k->have_child == 0) {
                pr_err("@have_child of array json key [%s] is false\n", k->key);
                return -EINVAL;
        }

        return 0;
}

int json_key_val_load_recursive(cJSON *curr_node,
                                json_key_t *curr_key,
                                size_t depth)
{
        cJSON *sub_node = NULL;
        json_key_t *sub_key = NULL;
        int err = 0;

        if (!curr_node || !curr_key)
                return -ENODATA;

        if (!is_cjson_type(curr_node->type, curr_key->cjson_type)) {
                pr_err("key [%s]: cjson type mismatched: key [0x%x] node [0x%x]\n",
                       curr_key->key, curr_key->cjson_type, curr_node->type);
                return -EINVAL;
        }

        // process for array node
        if (is_cjson_type(curr_node->type, cJSON_Array)) {
                size_t i = 0;

                // @have_child == 0 checked inside
                if ((err = json_array_key_check(curr_key)))
                        return err;

                // XXX: currently support mono type sub keys only.
                //      mixed type array data not supported yet.
                sub_key = curr_key->child[0];
                if (!sub_key) {
                        pr_err("sub key of array key [%s] is null\n", curr_key->key);
                        return -ENODATA;
                }

                cJSON_ArrayForEach(sub_node, curr_node) {
                        if (g_cfg.json_print)
                                json_node_print(sub_node, depth, &i);

                        if (i >= curr_key->ele_cnt) {
                                pr_warn("json array exceeds desc max array cnt: %zu\n",
                                        curr_key->ele_cnt);
                                break;
                        }

                        if ((err = json_array_key_update(curr_key, i, 1, 1)))
                                return err;

                        if (!curr_key->data_ref)
                                continue;

                        if ((err = json_sub_keys_update(curr_key)))
                                return err;

                        // mono type array must match sub key's cjson type
                        if (!is_cjson_type(sub_key->cjson_type, sub_node->type)) {
                                pr_dbg("array sub key type mismatched, next node\n");
                                continue;
                        }

                        // nameless 'object' or 'array' sub json nodes
                        if (is_cjson_type(sub_node->type, cJSON_Compound)) {
                                err = json_key_val_load_recursive(sub_node,
                                                                  sub_key,
                                                                  depth + 1);
                                if (err) {
                                        pr_err("failed to process #%zu of array [%s]\n",
                                               i, curr_node->string);
                                        return err;
                                }

                                // continue;
                                goto next_element;
                        }

                        // other json types: number, string, etc..
                        err = json_value_dump(sub_node, sub_key, curr_key);
                        if (err) {
                                pr_err("failed to process #%zu of array [%s]\n",
                                       i, curr_node->string);
                                return err;
                        }

next_element:
                        i++;
                }

                return 0;
        }

        if ((err = json_key_data_init(curr_key)))
                return err;

        if (is_cjson_type(curr_node->type, cJSON_Object)) {
                if ((err = json_obj_key_update(curr_key, 1)))
                        return (err == -ECANCELED) ? 0 : err;

                if ((err = json_sub_keys_update(curr_key)))
                        return err;
        }

        // process for object node
        cJSON_ArrayForEach(sub_node, curr_node) {
                if (g_cfg.json_print)
                        json_node_print(sub_node, depth, NULL);

                // find handler for sub node
                // have_child != 0 checked inside
                sub_key = json_sub_key_get(curr_key, sub_node->string);
                if (!sub_key) {
                        pr_notice("handler is not defined for json key [%s]\n",
                                  sub_node->string);
                        continue;
                }

                if (is_cjson_type(sub_node->type, cJSON_Compound)) {
                        err = json_key_val_load_recursive(sub_node, sub_key,
                                                          depth + 1);
                        if (err)
                                goto err_print;

                        continue;
                }

                // process for not grouped nodes (strings, number, boolean, etc)
                err = json_value_dump(sub_node, sub_key, curr_key);

err_print:
                if (err) {
                        pr_err_once("stack of key on error:\n");
                        // dump stack recursively on error occurs
                        json_node_print(sub_node, depth, NULL);
                        return err;
                }
        }

        return err;
}

int json_key_val_load(cJSON *root_node, json_key_t *root_key)
{
        return json_key_val_load_recursive(root_node, root_key, 0);
}

int json_decode(json_key_t *root_key, const char *text)
{
        cJSON *root_node;
        int err;

        if (!root_key || !text)
                return -EINVAL;

        root_node = cJSON_Parse(text);
        if (!root_node) {
                pr_err("cJSON_Parse() failed\n");
                return -EINVAL;
        }

        err = json_key_val_load(root_node, root_key);

        cJSON_Delete(root_node);

        return err;
}

int json_load(json_key_t *root_key, const char *path)
{
        char *text;
        int err;

        if (!path || !root_key)
                return -EINVAL;

        if (path[0] == '\0') {
                pr_err("@path is empty\n");
                return -ENODATA;
        }

        text = file_read(path);
        if (!text)
                return -EIO;

        err = json_decode(root_key, text);

        free(text);

        return err;
}

void *jkey_number_get(json_key_t *k)
{
        void *data_ref = k->data_ref;
        void *val = NULL;

        if (!data_ref)
                return NULL;

        if (k->data_ref_ptr) {
                data_ref = *(uint8_t **)data_ref;
                if (!data_ref)
                        return NULL;
        }

        // number should all have @data_sz defined
        if (!k->data_sz)
                return NULL;

        switch (k->data_type) {
        case D_FLOAT:
        case D_DOUBLE:
                val = calloc(1, k->data_sz);
                if (!val)
                        return NULL;

                memcpy(val, data_ref, k->data_sz);
                break;

        case D_UNSIGNED: // D_BOOLEAN
                val = calloc(1, sizeof(uint64_t));
                ptr_unsigned_word_read(data_ref, k->data_sz, val);
                break;

        case D_INTEGER:
        case D_SIGNED:
                val = calloc(1, sizeof(int64_t));
                ptr_signed_word_read(data_ref, k->data_sz, val);
                break;

        default:
                return NULL;
        }

        return val;
}

static int based_strint_convert(json_key_t *k, char **out)
{
        int64_t t = 0;
        int err = 0;
        size_t buf_len = 64 + 64;
        char *buf = calloc(1, buf_len);
        if (!buf)
                return -ENOMEM;

        if (k->data_type == D_SIGNED)
                ptr_signed_word_read(k->data_ref, k->data_sz, &t);

        if (k->data_type == D_UNSIGNED)
                ptr_unsigned_word_read(k->data_ref, k->data_sz, (uint64_t *)&t);

        switch (k->int_base) {
        case 2:
                if ((err = bin_snprintf(buf, buf_len, t, k->data_sz)))
                        goto err;
                break;
        case 8:
                snprintf(buf, buf_len, "%jo", t);
                break;
        case 10:
                snprintf(buf, buf_len, "%jd", t);
                break;
        case 16:
                snprintf(buf, buf_len, "0x%.*jx", k->data_sz * 2, t);
                break;
        default:
                pr_err("key [%s]: not supported integer base %d\n", k->key, k->int_base);
                break;
        }

        *out = buf;
        return err;

err:
        free(buf);
        return err;
}

int json_node_create(json_key_t *curr, json_key_t *parent, void *data)
{
        cJSON *node = NULL;
        void *val = jkey_number_get(curr);
        int ret = 0;

        // node goes here all with valid data pointed to

        switch (curr->cjson_type) {
        case cJSON_Array:
                node = cJSON_CreateArray();
                break;

        case cJSON_Object:
                // do not create node on NULL data node
                if (curr->base_ref && curr->data_ref_ptr) {
                        // curr->data_ref has NOT been dereferenced outside
                        if (*(uint8_t **)curr->base_ref == NULL) {
                                ret = -ECANCELED;
                                break;
                        }
                }

                node = cJSON_CreateObject();
                break;

        case cJSON_Number:
                if (!val)
                        break;

                switch (curr->data_type) {
                case D_UNSIGNED:
                        node = cJSON_CreateNumber(*(uint64_t *)val);
                        break;
                case D_INTEGER:
                case D_SIGNED:
                        node = cJSON_CreateNumber(*(int64_t *)val);
                        break;
                case D_FLOAT:
                        // FIXME: extend float to double
                        //        will introduce junk fraction parts
                        node = cJSON_CreateNumber(*(float *) val);
                        break;
                case D_DOUBLE:
                        node = cJSON_CreateNumber((*(double *)val));
                        break;
                }

                break;

        case cJSON_Boolean:
                if (!val)
                        break;

                node = cJSON_CreateBool(*(uint64_t *)val);
                break;

        case cJSON_String:
                if (!curr->data_ref) {
                        pr_warn("@data_ref of key [%s] is null\n", curr->key);
                        break;
                }

                // it's a number in json key
                if (val) {
                        // FIXME: did not verify optstrs[] access range
                        if (curr->optstrs) {
                                const char *optval = curr->optstrs[*(uint64_t *)val].optval;
                                if (!optval) {
                                        pr_err("key [%s]: invalid value of optstr: %ju\n",
                                               curr->key, *(uint64_t *)val);
                                        ret = -EINVAL;
                                        goto out;
                                }

                                node = cJSON_CreateString(optval);
                                break; // switch(cjson_type)
                        }

                        if (curr->int_base) {
                                char *buf = NULL;
                                if ((ret = based_strint_convert(curr, &buf)))
                                        goto out;

                                // there is a strdup() inside
                                node = cJSON_CreateString(buf);
                                free(buf);

                                break; // switch(json_type)
                        }

                        switch (curr->data_type) {
                        case D_UNSIGNED:
                                node = cJSON_CreateNumber(*(uint64_t *)val);
                                break; // switch(curr->data_type)
                        case D_INTEGER:
                        case D_SIGNED:
                                node = cJSON_CreateNumber(*(int64_t *)val);
                                break; // switch(curr->data_type)
                        default:
                                pr_err("unexpected data type of key [%s], bugged\n", curr->key);
                                ret = -EINVAL;
                                goto out;
                        }

                        break; // switch(cjson_type)
                }

                // strptr, strref case
                if (curr->data_ref_ptr) {
                        if (*(char **)curr->data_ref == NULL) {
                                // not to create empty strings in string array
                                if (parent->cjson_type != cJSON_Array)
                                        node = cJSON_CreateString("");

                                break;
                        }

                        node = cJSON_CreateString(*(char **)curr->data_ref);
                        break;
                }

                // strbuf: ensure null terminated
                if (curr->data_sz == 0) {
                        pr_err("strbuf key [%s] does not setup @data_sz\n", curr->key);
                } else {
                        ((char *)curr->data_ref)[curr->data_sz - 1] = '\0';
                }

                node = cJSON_CreateString(curr->data_ref);

                break;

        default:
                pr_warn("unhandled cjson type: 0x%x\n", curr->cjson_type);
                break;
        }

        if (!node)
                goto out;

        // override cjson_node
        curr->cjson_node = node;

        if (!parent) { // current node is root node
                if (!data) {
                        pr_err("root node pointer is not specified\n");
                        ret = -EINVAL;
                        goto out;
                }

                // root type must be compounded
                *(cJSON **)data = curr->cjson_node;
        } else {
                if (!parent->cjson_node) {
                        pr_err("parent [%s] cjson node is empty\n", parent->key);
                        ret = -ENODATA;
                        goto out;
                }

                switch (parent->cjson_type) {
                case cJSON_Array:
                        cJSON_AddItemToArray(parent->cjson_node, curr->cjson_node);
                        break;
                case cJSON_Object:
                        cJSON_AddItemToObject(parent->cjson_node, curr->key, curr->cjson_node);
                        break;
                default:
                        pr_err("parent [%s] cjson node is not compound type\n", parent->key);
                        ret = -EINVAL;
                        goto out;
                }
        }

out:
        if (val)
                free(val);

        return ret;
}

int json_key_traverse(json_key_t *curr, json_key_t *parent, void *data,
                      jkey_traverse_cb pre_cb, jkey_traverse_cb post_cb)
{
        json_key_t *sub;
        size_t i;
        int err;

        if (!curr)
                return 0;

        if (pre_cb) {
                if ((err = pre_cb(curr, parent, data)))
                        return (err == -ECANCELED) ? 0 : err;
        }

        if (!curr->have_child)
                goto call_post_cb;

        if (curr->cjson_type == cJSON_Array) {
                for (size_t j = 0; j < curr->ele_cnt; j++) {
                        if ((err = json_array_key_update(curr, j, 1, 0)))
                                return err;

                        if (!curr->data_ref)
                                continue;

                        if ((err = json_sub_keys_update(curr)))
                                return err;

                        for (i = 0, sub = curr->child[i]; sub != NULL; sub = curr->child[++i]) {
                                if ((err = json_key_traverse(sub, curr, data, pre_cb, post_cb)))
                                        return err;
                        }
                }
        } else { // handle for other types of curr key
                if ((err = json_obj_key_update(curr, 0)))
                        return (err == -ECANCELED) ? 0 : err;

                if ((err = json_sub_keys_update(curr)))
                        return err;

                for (i = 0, sub = curr->child[i]; sub != NULL; sub = curr->child[++i]) {
                        if ((err = json_key_traverse(sub, curr, data, pre_cb, post_cb)))
                                return err;
                }
        }

call_post_cb:
        if (post_cb) {
                if ((err = post_cb(curr, parent, data)))
                        return err;
        }

        return 0;
}

int json_key_free(json_key_t *curr, json_key_t *parent, void *priv)
{
        UNUSED_PARAM(parent);
        UNUSED_PARAM(priv);

        void *data_ref;
        int err;

        if (curr->cjson_type == cJSON_Array) {
                if (!curr->data_ref_ptr || !curr->data_malloc)
                        return 0;

                for (size_t i = 0; i < curr->ele_cnt; i++) {
                        if ((err = json_array_key_update(curr, i, 0, 0)))
                                return err;

                        if (!(data_ref = curr->data_ref))
                                continue;

                        if (*(uint8_t **)data_ref) {
                                free(*(uint8_t **)data_ref);
                                *(uint8_t **)data_ref = NULL;
                        }
                }

                return 0; // break out!
        }

        if (!(data_ref = curr->data_ref))
                return 0;

        if (!curr->data_ref_ptr || !curr->data_malloc)
                return 0;

        if (*(uint8_t **)data_ref) {
                free(*(uint8_t **)data_ref);
                *(uint8_t **)data_ref = NULL;
        }

        return 0;
}

// WARN: unreg pj sip, remove all accounts before calling json_key_recursive_free()
int json_key_recursive_free(json_key_t *root_key)
{
        int err;

        if (!root_key)
                return -EINVAL;

        err = json_key_traverse(root_key, NULL, NULL,
                                NULL, json_key_free);

        return err;
}

int json_key_to_node(json_key_t *root_key, cJSON **root_node)
{
        cJSON *node;
        int err;

        if (!root_key || !root_node || *root_node)
                return -EINVAL;

        err = json_key_traverse(root_key, NULL, &node,
                                json_node_create, NULL);
        if (err)
                goto failed;

        *root_node = node;

        return 0;

failed:
        if (node)
                cJSON_Delete(node);

        return err;
}

/**
 * json_encode() - generate json text
 * @param root_key: json key to generate json based on
 * @param text: json text, need to free outside
 * @param formatted: true to format text into multiple lines
 * @return 0 on success otherwise error code
 */
int json_encode(json_key_t *root_key, char **text, int formatted)
{
        cJSON *root_node = NULL;

        int err = 0;

        if (!root_key || !text)
                return -EINVAL;

        if (*text)
                pr_warn("@text is not cleaned\n");

        err = json_key_to_node(root_key, &root_node);
        if (err) {
                return err;
        }

        if (!root_node)
                return -ENODATA;

        /* cjson print will allocate text string */
        if (formatted)
                *text = cJSON_Print(root_node);
        else
                *text = cJSON_PrintUnformatted(root_node);

        if (root_node)
                cJSON_Delete(root_node);

        return err;
}

int json_save(json_key_t *root_key, const char *path, int formatted)
{
        char *text = NULL;
        int err;

        if (!path || !root_key)
                return -EINVAL;

        /* allocate text string inside */
        err = json_encode(root_key, &text, formatted);
        if (err)
                goto out;

        // this string buffer needs to be freed at external
        err = file_write(path, text, strlen(text));

out:
        if (text)
                free(text);

        return err;
}
