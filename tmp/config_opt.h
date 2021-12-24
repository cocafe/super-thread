#ifndef __VOIP_PHONE_CFG_H__
#define __VOIP_PHONE_CFG_H__

#include <stdarg.h>

#include <pjsua.h>

#include "utils.h"
#include "nlslic.h"

#include "cJSON.h"

#define OPTION_PATH_LEN                 (256)
#define OPTION_STR_LEN                  (128)

#define PJ_SRV_CNT                      (4)
#define PJ_ACC_CNT                      (4)
#define PJ_DNS_CNT                      (4)
#define PJ_PRX_CNT                      (4)
#define PJ_STUN_CNT                     (2)
#define PJ_OBPRX_CNT                    (4)
#define PJ_CODEC_CNT                    (16)
#define PJ_SRV_SEL_CNT                  (4)
#define PJ_PRX_SEL_CNT                  (4)

#define DTMF_PRESET_DEF                 (DTMF_PRESET_A_C)

enum outgoing_opt {
        OUTGOING_BY_PREFIX = 0, // debug purpose: prefix ## to call voip
        OUTGOING_VOLTE,
        OUTGOING_VOIP,
        OUTGOING_DIGITMAP,
        NUM_OUTGOING_OPTS,
};

enum incoming_opt {
        INCOMING_ALLOW_ALL = 0,
        INCOMING_VOLTE_ONLY,
        INCOMING_VOIP_ONLY,
        NUM_INCOMING_OPTS,
};

// NOTE:
//      this order is used to
//      detected ipv6 enabled or not
//      in config_apply(). change with caution.
enum sip_proto_opt {
        SIP_PROTO_UDP = 0,
        SIP_PROTO_TCP,
        SIP_PROTO_TLS,
        SIP_PROTO_UDP6,
        SIP_PROTO_TCP6,
        SIP_PROTO_TLS6,
        NUM_SIP_PROTOS,
};

enum dtmf_preset_opt {
        DTMF_PRESET_A_C = 0,
        DTMF_PRESET_D_C,
        DTMF_PRESET_SPECIAL,
        NUM_DTMF_PRESETS,
};

enum dtmf_send_opt {
        DTMF_INBAND = 0,
        DTMF_RFC2833,
        DTMF_SIPINFO, // OUTBAND
        NUM_DTMF_SEND_OPTS,
};

enum use_proxy_opt {
        USE_PROXY_NONE = 0,
        USE_PROXY_OB,
        USE_PROXY_ACC,
        USE_PROXY_ALL,
        NUM_PROXY_REG_OPTS,
};

enum offhk_act_opt {
        OFFHK_REJECT = 0,
        OFFHK_JUMP,
        OFFHK_DEFER_CALL,
        NUM_OFFHK_ACTS,
};

enum ec_alg_opt {
        EC_ALG_DEFAULT = 0,
        EC_ALG_SPEEX,
        EC_ALG_SUPPRESS,
        EC_ALG_WEBRTC,        // disabled
        NUM_EC_ALGS,
};

enum sess_timer_opt {
        SESS_TIMER_INACTIVE = 0,
        SESS_TIMER_OPTIONAL,
        SESS_TIMER_MANDATORY,
        SESS_TIMER_ALWAYS,
        NUM_SESS_TIMER_OPTS,
};

enum qos_type_opt {
        QOS_TYPE_BEST_EFFORT = 0,
        QOS_TYPE_BACKGROUND,
        QOS_TYPE_VIDEO,
        QOS_TYPE_VOICE,
        QOS_TYPE_CONTROL,
        QOS_TYPE_SINGAL,
        NUM_QOS_TYPES,
};

enum prack_opt {
        PRACK_DISABLED = 0,
        PRACK_MANDATORY,
        PRACK_OPTIONAL,
        NUM_PRACK_OPTS,
};

enum ec_lvl_opt {
        EC_LVL_DEFAULT = 0,
        EC_LVL_CONSERV,
        EC_LVL_MODERATE,
        EC_LVL_AGGRESSIVE,
        NUM_EC_LVLS,
};

#define D_GENERIC                       (BIT(0U)) // reserved
#define D_SIGNED                        (BIT(1U))
#define D_UNSIGNED                      (BIT(2U))
#define D_STRING                        (BIT(3U))
#define D_DOUBLE                        (BIT(4U))
#define D_FLOAT                         (BIT(5U))

// this is an OR result, using it in case should result as SIGNED
#define D_INTEGER                       (D_SIGNED | D_UNSIGNED)

#define D_BOOLEAN                       D_UNSIGNED
#define D_BOOL_TRUE                     (1)
#define D_BOOL_FALSE                    (0)

typedef struct optstr optstr_t;
typedef struct opt_desc optdesc_t;
typedef struct json_key json_key_t;

/*
 * these strings are used to convert optarg to int
 * need to terminated by NULL
 * and NO holes are allowed
 * and first enum must start with ZERO
 */
struct optstr {
        const char *optval;
        const char *desc;
};

/*
 * struct option:
 *      char *name:     long option string
 *      int has_arg:    { no_argument, required_argument, [X]optional_argument }
 *
 *      int *flag:      1. pointer to flag variable to write
 *                      2. if null pointer, then val is the short option
 *
 *      int val:        1. value that write to flag when option triggers if @flag is not NULL
 *                      2. or shorten option char
 *
 * struct option long_opts[] = {
 *         { "verbose",        no_argument,       &verbose_output, 1   },
 *         { "config",         required_argument, NULL,            'c' },
 *         { "sip_server",     required_argument, NULL,            0   },
 *         { 0,                0,                 0,               0   },
 * };
 */

struct opt_desc {
        char            short_opt;
        char            *long_opt;      // hmm, use strcmp() to find matched...

        int             has_arg;        // { no_argument, required_argument, [X]optional_argument }

        int             to_set;         // if (@short_opt == 0 && has_arg == no_argument)
                                        //         *(int *)param = to_set; // by getopt() internal

        void           *data;           // data to modify
        size_t          data_sz;
        void           *data_def;       // if @data_def != NULL, @data will be inited with @data_def
                                        // if @data_def == NULL, @data will be reset with 0 by @data_sz
        uint32_t        data_type;      // @data type

        int64_t         min;            // optarg_to_int: verify input: >= @min
                                        // maybe negative, thus int64_t

        int64_t         max;            // optarg_to_int: verify input: <= @max

        const optstr_t *optstrs;        // optstr_to_int: config string array
                                        //                cfg value is matched element index

        int             (*parse)(void *data, char *optarg, size_t vargc, ...);

        char           *help[];         // description in help text, '\n' is not required.
                                        // one element per line
                                        // must terminate with NULL as last element
                                        // first element is used in config_dump()
};

int optarg_to_int(void *data, char *optarg, size_t vargc, ...);
int optarg_to_str(void *data, char *optarg, size_t vargc, ...);
int optstr_to_int(void *data, char *optarg, size_t vargc, ...);

struct pj_srv {
        char           *uri;
        size_t          uri_sz;
        char           *url;
        uint16_t        port;
};

enum {
        SIPACC_STATE_DISABLED = 0,
        SIPACC_STATE_UP,
        SIPACC_STATE_INIT,
        SIPACC_STATE_REGING,
        SIPACC_STATE_UNREGING,
        SIPACC_STATE_ERR,
        SIPACC_STATE_TESTING,
        SIPACC_STATE_DOWN,       /* Quiescent */
        NUM_SIPACC_STATES,
};

struct pj_acc {
        struct {
                char     *reg;
                size_t    reg_sz;
                char     *id;
                size_t    id_sz;
        } uri;

        char             *user;
        char             *passwd;
        char             *realm;
        char             *id_uri; // sip:%s@%s

        struct pj_srv    *reg_srv;
        pjsua_acc_id      pj_acc_id;
        size_t            pj_acc_idx;

        struct {
                struct {
                        char      datetime[24];
                        char      regsrv[64];
                        char      reason[32];
                        char     *code_str;
                        int16_t   code;
                } last_err;

                char     *regsrv;
                int16_t   next_expire;
                int8_t    state;
        } reg_stat;

        int8_t            srv_sel[PJ_SRV_SEL_CNT];
        int8_t            prx_sel[PJ_PRX_SEL_CNT];

        struct {
                char     *uri_param;

                uint8_t   is_default;
                uint8_t   mwi;
                uint8_t   prack;
                uint8_t   use_ims;

                uint8_t   publish;
                uint8_t   use_stun;
                uint8_t   sdp_nat_rewrite;
                uint8_t   uri_with_port;
        } opt;

        uint8_t           enabled;      /* !!! */

        pj_time_val       reg_last_switch;
        volatile uint8_t  reg_failed;

        uint8_t           last_srv_sel;

        struct { // all in secs
                uint8_t   use_proxy;

                int16_t   retry_intv;
                int16_t   reg_timeout;

                int16_t   unreg_timeout;
                int16_t   hb_intv;

                char     *hb_content;
        } reg;

        struct { // all in secs
                uint8_t   use_timer;
                int16_t   expire_secs;
                int16_t   min_expire_secs;
        } timer;
};

struct pj_tp_cfg {
        uint16_t                port;
        uint16_t                port_min;
        uint16_t                port_max;
        char                   *bind;
        char                   *public;

        struct {
                uint8_t         enabled;
                pj_qos_type     type;
                uint8_t         dscp;
        } qos;
};

struct pj_trans {
        int                     proto;
        int                     proto_pj;       // converted pj value

        char                   *dns[PJ_DNS_CNT];

        struct pj_tp_cfg        rtp;
        struct pj_tp_cfg        session;

        uint8_t                 ipv6;
        uint8_t                 tcp_proxy;

        uint8_t                 stun_enabled;
        uint8_t                 have_stun;
        uint8_t                 use_stun2;
};

struct pj_audio {
        struct {
                int32_t         bridge;
                int32_t         device;
        } clk_rate;

        struct {
                int16_t         capture;
                int16_t         playback;
        } buffer_ms;

        struct {
                uint8_t         enabled;
                uint8_t         use_sw;
                uint8_t         alg;
                uint8_t         noise_suppress;
                int16_t         level;
                int16_t         tail_ms;
        } ec;

        struct {
                int16_t         max_ms;
                struct {
                        int16_t init;
                        int16_t min;
                        int16_t max;
                } prefetch_ms;
        } jitter_buf;

        struct {
                float           capture;
                float           playback;
        } volume;

        uint16_t                vad_enabled;
        int16_t                 quality;
        int16_t                 frame_ptime;
};

struct pj_codec_cfg {
        char   *name;
        uint8_t enabled;
        uint8_t prio;
        int16_t ptime;
        int8_t  vad; // this will override by audio.vad_enabled
        int8_t  cng;
        int8_t  penh;
        int8_t  plc;
};

struct pj_cfg {
        uint8_t                 log_lvl;
        uint8_t                 sipmsg_dbg;

        uint8_t                 dtmf_send;
//      uint8_t                 hookflash_send;

        uint8_t                 reg_failed_thrs;
        uint8_t                 reg_switch_intv;
        int8_t                  default_acc;

        struct pj_trans         trans;
        struct pj_audio         audio;
        struct pj_codec_cfg    *codecs[PJ_CODEC_CNT];
        struct pj_acc          *account[PJ_ACC_CNT];
        struct pj_srv          *obproxy[PJ_OBPRX_CNT];
        struct pj_srv          *regsrv[PJ_SRV_CNT];
        struct pj_srv          *proxy[PJ_PRX_CNT];
        struct pj_srv          *stun[PJ_STUN_CNT];
};

struct ip_port {
        char                    addr[IPV6_STRLEN_MAX];
        uint16_t                port;
};

struct rtp_pkt_stat {
        size_t                  discard;
        size_t                  dup;
        size_t                  loss;
        size_t                  reorder;
};

struct rtp_stream_stat {
        size_t                  avg_kbps;
        size_t                  avg_jitter;
        size_t                  avg_rtt;
        size_t                  bytes;
        size_t                  pkts;
        struct rtp_pkt_stat     pkt_stat;
};

struct rtp_stat {
        struct ip_port          local;
        struct ip_port          peer;

        char                    codec[16];
        uint32_t                sample_rate;

        struct rtp_stream_stat  tx;
        struct rtp_stream_stat  rx;
};

struct call_rec {
        uint8_t                 direction;
        uint8_t                 proto;
        uint8_t                 state;

        time_t                  datetime; // epoch
        uint32_t                duration;
        char                   *number;
        char                   *account;

        struct {
                uint16_t        code;
                char           *reason;
        } error;

        struct rtp_stat        *rtp;
};

struct rtp_total {
        size_t                  pkt_send;
        size_t                  pkt_recv;
        size_t                  pkt_lost;
        size_t                  byte_send;
        size_t                  byte_recv;
};

struct call_cnt {
        uint32_t        attempted;
        uint32_t        received;
        uint32_t        answered;
        uint32_t        connected;
        uint32_t        failed;
        uint32_t        interrupted;
};

struct call_stat {
        struct call_cnt         incoming;
        struct call_cnt         outgoing;

        struct rtp_total        *rtp_total;
        size_t                  total_secs;
};

// TODO: can be dynamic but may be complex
#define VOIP_CALL_REC_CNT       (10)
#define VOLTE_CALL_REC_CNT      (10)

struct call_stats {
        struct call_stat        stat_voip;
        struct call_stat        stat_volte;
        struct call_rec         *rec_voip[VOIP_CALL_REC_CNT];
        struct call_rec         *rec_volte[VOLTE_CALL_REC_CNT];
        size_t voip_rec_next;   // idx
        size_t volte_rec_next;  // idx
};

struct config {
        char            zlog_conf[OPTION_PATH_LEN];
        char            json_cfg[OPTION_PATH_LEN];
        char            sip_stats[OPTION_PATH_LEN];
        char            call_stats[OPTION_PATH_LEN];
        char            init_flag[OPTION_PATH_LEN];

        struct pj_cfg   pj;

        uint8_t         json_print;
        uint8_t         stdin_dbg;

        uint8_t         voip_enabled;
        uint8_t         volte_enabled;

        struct {
                uint8_t force_reset;
                uint8_t no_slic;

                struct {
                        int16_t min_ms;
                        int16_t max_ms;
                } hookflash;

                struct {
                        float playback;
                        float capture;
                } gain_dB;

                struct {
                        int16_t vrms;
                } ringing;
        } slic;

        struct {
                uint8_t cell_lock;
                char    cell_unlock_flag[OPTION_PATH_LEN];

                uint8_t dial_on_hash;
                uint8_t outgoing;
                uint8_t incoming;
                uint8_t mcid_service;

                uint8_t holding; // enabled
                uint8_t waiting; // enabled
                uint8_t auto_answer;

                struct {
                        uint8_t enabled;
                        char   *uri;    // conference uri
                } three_way;

                struct {
                        uint8_t action;
                        char   *uri;
                } offhk_act;

                struct {
                        uint8_t enabled;
                        char   *uri;
                } hotline;
        } call_opt;

        struct {
                uint16_t offset; // minute
                uint8_t dst;
        } tz;

        struct {
                uint8_t enabled;
        } digit_map;

        struct {
                uint8_t enabled;
                uint8_t method;

                struct {
                        uint8_t method;
                        dtmf_cid_cfg cfg;
                } dtmf;

                struct {
                        uint8_t method;
                        uint8_t modulation;
                        uint8_t time_sync;
                        char *msg_format; // TODO
                        // char *preset;
                } fsk;
        } cid;

        struct {
                int16_t hangtone;
                int16_t busytone;
                int16_t ringing;
        } duration;

        struct {
                uint16_t dialout_hash;
                uint16_t offhk_wo_dial;
                uint16_t dialout_wait; // not allowed to set -1?
                uint16_t noanswer_wait;
        } timer;
};

extern struct config g_cfg;
extern struct pj_cfg *g_pj_cfg;
extern struct call_stats g_call_stats;

extern dtmf_cid_cfg dtmf_presets[];

extern const optstr_t optstrs_outgoing[];
extern const optstr_t optstrs_incoming[];
extern const optstr_t optstrs_cid_method[];
extern const optstr_t optstrs_dtmf_method[];
extern const optstr_t optstrs_dtmf_presets[];
extern const optstr_t optstrs_fsk_mod[];
extern const optstr_t optstrs_fsk_method[];
extern const optstr_t optstrs_sip_proto[];
extern const optstr_t optstrs_dfmt_send[];
extern const optstr_t optstrs_reg_use_proxy[];
extern const optstr_t optstrs_offhk_act[];
extern const optstr_t optstrs_ec_alg[];
extern const optstr_t optstrs_sess_timer[];
extern const optstr_t optstrs_qos_type[];
//extern const optstr_t optstrs_prack[];
extern const optstr_t optstrs_ec_lvl[];
extern const optstr_t optstrs_sipacc_state[];

#define pjval_conv_safe(dst, src, pjval)                                     \
do {                                                                         \
        if ((size_t)(src) >= ARRAY_SIZE((pjval))) {                          \
                pr_err("%s:%d: value overflows pjval array\n",               \
                       __FILE__, __LINE__);                                  \
                break;                                                       \
        }                                                                    \
                                                                             \
        if ((size_t)((pjval)[(src)]) >                                       \
            GENMASK((BITS_PER_BYTE * sizeof((src))) - 1U, 0U)) {             \
                pr_err("%s:%d dest cannot hold such big pjval,"              \
                       "program bugged\n", __FILE__, __LINE__);              \
                break;                                                       \
        }                                                                    \
                                                                             \
        (dst) = (pjval)[(src)];                                              \
} while(0)

int longopts_parse(int argc, char *argv[]);

int config_init(struct config *cfg);
int config_dump(struct config *cfg);
int config_apply(struct config *cfg);

#endif /* __VOIP_PHONE_CFG_H__ */