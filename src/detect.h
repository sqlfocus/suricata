/* Copyright (C) 2007-2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_H__
#define __DETECT_H__

#include "suricata-common.h"

#include "flow.h"

#include "detect-engine-proto.h"
#include "detect-reference.h"
#include "detect-metadata.h"
#include "detect-engine-register.h"
#include "packet-queue.h"

#include "util-prefilter.h"
#include "util-mpm.h"
#include "util-spm.h"
#include "util-hash.h"
#include "util-hashlist.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-radix-tree.h"
#include "util-file.h"
#include "reputation.h"

#include "detect-mark.h"

#include "stream.h"

#include "util-var-name.h"

#include "app-layer-events.h"

#define DETECT_MAX_RULE_SIZE 8192

#define DETECT_TRANSFORMS_MAX 16

/** default rule priority if not set through priority keyword or via
 *  classtype. */
#define DETECT_DEFAULT_PRIO 3    /* 默认优先级: 未设定优先级或类型的识别规则 */

/* forward declarations for the structures from detect-engine-sigorder.h */
struct SCSigOrderFunc_;
struct SCSigSignatureWrapper_;

/*
  The detection engine groups similar signatures/rules together. Internally a
  tree of different types of data is created on initialization. This is it's
  global layout:

   For TCP/UDP

   - Flow direction
   -- Protocol
   -=- Dst port

   For the other protocols

   - Flow direction
   -- Protocol
*/

/* holds the values for different possible lists in struct Signature.
 * These codes are access points to particular lists in the array
 * Signature->sm_lists[DETECT_SM_LIST_MAX]. */
enum DetectSigmatchListEnum {
    DETECT_SM_LIST_MATCH = 0,  /* 逐包匹配, 如 DETECT_TCPMSS */
    DETECT_SM_LIST_PMATCH,     /* pattern式匹配，支持fast pattern, 加入 sm_fp_support_smlist_list */

    /* base64_data keyword uses some hardcoded logic so consider
     * built-in
     * TODO convert to inspect engine */
    DETECT_SM_LIST_BASE64_DATA,/* */

    /* list for post match actions: flowbit set, flowint increment, etc */
    DETECT_SM_LIST_POSTMATCH,  /* 匹配规则后的动作, 如 DETECT_BYPASS/DETECT_CONFIG 等 */

    DETECT_SM_LIST_TMATCH,     /* 标签匹配, 由tag关键字设置, 用于给主机/流打标 */

    /* lists for alert thresholding and suppression */
    DETECT_SM_LIST_SUPPRESS,   /* DetectThresholdData, 匹配threshold.config中的suppress规则 */
    DETECT_SM_LIST_THRESHOLD,  /* 匹配threshold.config中的threshold规则 */

    DETECT_SM_LIST_MAX,                                /* 此以前为静态索引 */

    /* start of dynamically registered lists */
    DETECT_SM_LIST_DYNAMIC_START = DETECT_SM_LIST_MAX, /* 动态注册索引 */
};

/* used for Signature->list, which indicates which list
 * we're adding keywords to in cases of sticky buffers like
 * file_data */
#define DETECT_SM_LIST_NOTSET INT_MAX

/*
 * DETECT ADDRESS
 */

/* a is ... than b */
enum {
    ADDRESS_ER = -1, /**< error e.g. compare ipv4 and ipv6 */
    ADDRESS_LT,      /**< smaller              [aaa] [bbb] */
    ADDRESS_LE,      /**< smaller with overlap [aa[bab]bb] */
    ADDRESS_EQ,      /**< exactly equal        [abababab]  */
    ADDRESS_ES,      /**< within               [bb[aaa]bb] and [[abab]bbb] and [bbb[abab]] */
    ADDRESS_EB,      /**< completely overlaps  [aa[bbb]aa] and [[baba]aaa] and [aaa[baba]] */
    ADDRESS_GE,      /**< bigger with overlap  [bb[aba]aa] */
    ADDRESS_GT,      /**< bigger               [bbb] [aaa] */
};

#define ADDRESS_FLAG_NOT            0x01 /**< address is negated */

/** \brief address structure for use in the detection engine.
 *
 *  Contains the address information and matching information.
 */
typedef struct DetectAddress_ {
    /** address data for this group */
    Address ip;
    Address ip2;

    /** flags affecting this address */
    uint8_t flags;

    /** ptr to the previous address in the list */
    struct DetectAddress_ *prev;
    /** ptr to the next address in the list */
    struct DetectAddress_ *next;
} DetectAddress;

/** Address grouping head. IPv4 and IPv6 are split out */
typedef struct DetectAddressHead_ {
    DetectAddress *ipv4_head;
    DetectAddress *ipv6_head;
} DetectAddressHead;


typedef struct DetectMatchAddressIPv4_ {
    uint32_t ip;    /**< address in host order, start of range */
    uint32_t ip2;   /**< address in host order, end of range */
} DetectMatchAddressIPv4;

typedef struct DetectMatchAddressIPv6_ {
    uint32_t ip[4];
    uint32_t ip2[4];
} DetectMatchAddressIPv6;

/*
 * DETECT PORT
 */

/* a is ... than b */
enum {
    PORT_ER = -1, /* error e.g. compare ipv4 and ipv6 */
    PORT_LT,      /* smaller              [aaa] [bbb] */
    PORT_LE,      /* smaller with overlap [aa[bab]bb] */
    PORT_EQ,      /* exactly equal        [abababab]  */
    PORT_ES,      /* within               [bb[aaa]bb] and [[abab]bbb] and [bbb[abab]] */
    PORT_EB,      /* completely overlaps  [aa[bbb]aa] and [[baba]aaa] and [aaa[baba]] */
    PORT_GE,      /* bigger with overlap  [bb[aba]aa] */
    PORT_GT,      /* bigger               [bbb] [aaa] */
};

#define PORT_FLAG_ANY           0x01 /**< 'any' special port */
#define PORT_FLAG_NOT           0x02 /**< negated port */
#define PORT_SIGGROUPHEAD_COPY  0x04 /**< sgh is a ptr copy */

/** \brief Port structure for detection engine */
typedef struct DetectPort_ {
    uint16_t port;     /* 对于"80"，port=port2=80 */
    uint16_t port2;    /* 对于"80:89"，port=80，port2=89 */
                       /* 对于"any": port=0, port2=65535 */
    uint8_t flags;     /* 对于"!80", port=port2=80, 并设置 PORT_FLAG_NOT */

    /* signatures that belong in this group
     *
     * If the PORT_SIGGROUPHEAD_COPY flag is set, we don't own this pointer
     * (memory is freed elsewhere).
     */
    struct SigGroupHead_ *sh;  /* 包含对应的 Signature 组，以加速匹配 */

    struct DetectPort_ *prev;
    struct DetectPort_ *next;
} DetectPort;

/* Signature flags */
/** \note: additions should be added to the rule analyzer as well */

#define SIG_FLAG_SRC_ANY                BIT_U32(0)  /**< source is any */
#define SIG_FLAG_DST_ANY                BIT_U32(1)  /**< destination is any */
#define SIG_FLAG_SP_ANY                 BIT_U32(2)  /**< source port is any */
#define SIG_FLAG_DP_ANY                 BIT_U32(3)  /**< destination port is any */

#define SIG_FLAG_NOALERT                BIT_U32(4)  /**< no alert flag is set */
#define SIG_FLAG_DSIZE                  BIT_U32(5)  /* dsize关键字 *< signature has a dsize setting */
#define SIG_FLAG_APPLAYER               BIT_U32(6)  /* 规则应用于应用层, 而不是报文 *< signature applies to app layer instead of packets */
#define SIG_FLAG_IPONLY                 BIT_U32(7)  /* 无内容检测规则, 无方向, 基于IP数据的匹配 *< ip only signature */

// vacancy

#define SIG_FLAG_REQUIRE_PACKET         BIT_U32(9)  /* 匹配时需要报文, 如ttl/DETECT_TTL *< signature is requiring packet match */
#define SIG_FLAG_REQUIRE_STREAM         BIT_U32(10) /* flow关键字 *< signature is requiring stream match */

#define SIG_FLAG_MPM_NEG                BIT_U32(11) /* 选做prefilter的匹配 Signature->init_data->mpm_sm 带有取反操作 */

#define SIG_FLAG_FLUSH                  BIT_U32(12) /**< detection logic needs stream flush notification */

// vacancies

#define SIG_FLAG_REQUIRE_FLOWVAR        BIT_U32(17) /**< signature can only match if a flowbit, flowvar or flowint is available. */

#define SIG_FLAG_FILESTORE              BIT_U32(18) /**< signature has filestore keyword */

#define SIG_FLAG_TOSERVER               BIT_U32(19)
#define SIG_FLAG_TOCLIENT               BIT_U32(20)

#define SIG_FLAG_TLSSTORE               BIT_U32(21)

#define SIG_FLAG_BYPASS                 BIT_U32(22)

#define SIG_FLAG_PREFILTER              BIT_U32(23) /* 可为prefilter引擎所用 *< sig is part of a prefilter engine */

/** Proto detect only signature.
 *  Inspected once per direction when protocol detection is done. */
#define SIG_FLAG_PDONLY                 BIT_U32(24) /* 仅用于协议识别的规则 */
/** Info for Source and Target identification */
#define SIG_FLAG_SRC_IS_TARGET          BIT_U32(25)
/** Info for Source and Target identification */
#define SIG_FLAG_DEST_IS_TARGET         BIT_U32(26)

#define SIG_FLAG_HAS_TARGET             (SIG_FLAG_DEST_IS_TARGET|SIG_FLAG_SRC_IS_TARGET)

/* signature init flags */
#define SIG_FLAG_INIT_DEONLY                BIT_U32(0)  /**< decode event only signature */
#define SIG_FLAG_INIT_PACKET                BIT_U32(1)  /**< signature has matches against a packet (as opposed to app layer) */
#define SIG_FLAG_INIT_FLOW                  BIT_U32(2)  /**< signature has a flow setting */
#define SIG_FLAG_INIT_BIDIREC               BIT_U32(3)  /* 五元组方向为'<>', *< signature has bidirectional operator */
#define SIG_FLAG_INIT_FIRST_IPPROTO_SEEN    BIT_U32(4)  /** < signature has seen the first ip_proto keyword */
#define SIG_FLAG_INIT_HAS_TRANSFORM         BIT_U32(5)
#define SIG_FLAG_INIT_STATE_MATCH           BIT_U32(6)  /* 应用检测, 需要状态 *< signature has matches that require stateful inspection */
#define SIG_FLAG_INIT_NEED_FLUSH            BIT_U32(7)  /* 检测需要和流同步 */
#define SIG_FLAG_INIT_PRIO_EXPLICT          BIT_U32(8)  /* 优先级由规则"priority"字段明确指定, *< priority is explicitly set by the priority keyword */
#define SIG_FLAG_INIT_FILEDATA              BIT_U32(9)  /* file.data/file_data关键字 *< signature has filedata keyword */
#define SIG_FLAG_INIT_DCERPC                BIT_U32(10) /**< signature has DCERPC keyword */

/* signature mask flags */
/** \note: additions should be added to the rule analyzer as well */
#define SIG_MASK_REQUIRE_PAYLOAD            BIT_U8(0)    /* 内容检测，需要加载报文 */
#define SIG_MASK_REQUIRE_FLOW               BIT_U8(1)
#define SIG_MASK_REQUIRE_FLAGS_INITDEINIT   BIT_U8(2)    /* SYN, FIN, RST */
#define SIG_MASK_REQUIRE_FLAGS_UNUSUAL      BIT_U8(3)    /* URG, ECN, CWR */
#define SIG_MASK_REQUIRE_NO_PAYLOAD         BIT_U8(4)
#define SIG_MASK_REQUIRE_DCERPC             BIT_U8(5)    /* require either SMB+DCE or raw DCE */
// vacancy
#define SIG_MASK_REQUIRE_ENGINE_EVENT       BIT_U8(7)

/* for now a uint8_t is enough */
#define SignatureMask uint8_t

#define DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH 0x0004

#define FILE_SIG_NEED_FILE          0x01
#define FILE_SIG_NEED_FILENAME      0x02
#define FILE_SIG_NEED_MAGIC         0x04    /**< need the start of the file */
#define FILE_SIG_NEED_FILECONTENT   0x08
#define FILE_SIG_NEED_MD5           0x10
#define FILE_SIG_NEED_SHA1          0x20
#define FILE_SIG_NEED_SHA256        0x40
#define FILE_SIG_NEED_SIZE          0x80

/* Detection Engine flags */
#define DE_QUIET           0x01     /**< DE is quiet (esp for unittests) */

typedef struct IPOnlyCIDRItem_ {
    /* address data for this item */
    uint8_t family;
    /* netmask in CIDR values (ex. /16 /18 /24..) */
    uint8_t netmask;
    /* If this host or net is negated for the signum */
    uint8_t negated;

    uint32_t ip[4];
    SigIntId signum;   /* 对应的 Signature->num */

    /* linked list, the header should be the biggest network */
    struct IPOnlyCIDRItem_ *next;

} IPOnlyCIDRItem;

/** \brief Used to start a pointer to SigMatch context
 * Should never be dereferenced without casting to something else.
 */
typedef struct SigMatchCtx_ {
    int foo;
} SigMatchCtx;

/** 描述某规则的某个匹配; \brief a single match condition for a signature */
typedef struct SigMatch_ {
    uint8_t type;     /* DETECT_FLOW */
    uint16_t idx;     /* 在->init_data->smlists[]链表中的索引, [0, N] */
    SigMatchCtx *ctx; /* 对应类型的特殊数据, DETECT_FLOW -> DetectFlowData */
    struct SigMatch_ *next;               /* DETECT_CONTENT -> DetectContentData */
    struct SigMatch_ *prev;
} SigMatch;

/** \brief Data needed for Match() */
typedef struct SigMatchData_ {
    uint8_t type;      /* 规则类型, DETECT_FLOW, *< match type */
    uint8_t is_last;   /* 本类型最后一条规则, *< Last element of the list */
    SigMatchCtx *ctx;  /**< plugin specific data */
} SigMatchData;  /* 和 SigMatch 对等 */

struct DetectEngineThreadCtx_;// DetectEngineThreadCtx;

/* inspection buffer is a simple structure that is passed between prefilter,
 * transformation functions and inspection functions.
 * Initially setup with 'orig' ptr and len, transformations can then take
 * then and fill the 'buf'. Multiple transformations can update the buffer,
 * both growing and shrinking it.
 * Prefilter and inspection will only deal with 'inspect'. */

typedef struct InspectionBuffer {
    const uint8_t *inspect; /* 指向待检测内存, = ->buf; *< active pointer, points either to ::buf or ::orig */
    uint64_t inspect_offset;
    uint32_t inspect_len;   /* 待检测内存长度 *< size of active data. See to ::len or ::orig_len */
    uint8_t flags;          /**< DETECT_CI_FLAGS_* for use with DetectEngineContentInspection */

    uint32_t len;           /* ->buf有效数据长度, *< how much is in use */
    uint8_t *buf;           /* 动态分配, 存储->orig变换后的结果 */
    uint32_t size;          /* ->buf大小 *< size of the memory allocation */

    uint32_t orig_len;
    const uint8_t *orig;    /* 指向待检测内存的原始数据 */
} InspectionBuffer;

/* inspection buffers are kept per tx (in det_ctx), but some protocols
 * need a bit more. A single TX might have multiple buffers, e.g. files in
 * SMTP or DNS queries. Since all prefilters+transforms run before the
 * individual rules need the same buffers, we need a place to store the
 * transformed data. This array of arrays is that place. */

typedef struct InspectionBufferMultipleForList {
    InspectionBuffer *inspection_buffers;
    uint32_t size;      /**< size in number of elements */
    uint32_t max:31;    /**< max id in use in this run */
    uint32_t init:1;    /**< first time used this run. Used for clean logic */
} InspectionBufferMultipleForList;

typedef struct TransformData_ {
    int transform;    /* sigmatch_table[] 索引, 如 DETECT_TRANSFORM_STRIP_WHITESPACE */
    void *options;
} TransformData;

typedef struct DetectEngineTransforms {
    TransformData transforms[DETECT_TRANSFORMS_MAX];  /* 转换数组, 如去除空字符等 */
    int cnt;  /* 数量 */
} DetectEngineTransforms;

/** callback for getting the buffer we need to prefilter/inspect */
typedef InspectionBuffer *(*InspectionBufferGetDataPtr)(
        struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, const uint8_t flow_flags,
        void *txv, const int list_id);

typedef int (*InspectEngineFuncPtr)(ThreadVars *tv,
        struct DetectEngineCtx_ *de_ctx, struct DetectEngineThreadCtx_ *det_ctx,
        const struct Signature_ *sig, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *tx, uint64_t tx_id);

struct DetectEngineAppInspectionEngine_;

typedef int (*InspectEngineFuncPtr2)(
        struct DetectEngineCtx_ *de_ctx, struct DetectEngineThreadCtx_ *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine,
        const struct Signature_ *s,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);
/* 应用层检测引擎, 链接入 g_app_inspect_engines */
typedef struct DetectEngineAppInspectionEngine_ {
    AppProto alproto;         /* 应用层协议, ALPROTO_HTTP */
    uint8_t dir;              /* 0 - SIG_FLAG_TOSERVER */
    uint8_t id;               /* 单规则的引擎列表, 索引 *< per sig id used in state keeping */
    uint16_t mpm:1;           /* 是否支持多模检测 */
    uint16_t stream:1;
    uint16_t sm_list:14;      /* 检测类型索引, DetectBufferType->id */
    int16_t progress;         /* 应用解析所处的阶段, 如 “http_uri” -> HTP_REQUEST_LINE */

    /* \retval 0 No match.  Don't discontinue matching yet.  We need more data.
     *         1 Match.
     *         2 Sig can't match.
     *         3 Special value used by filestore sigs to indicate disabling
     *           filestore for the tx.
     */
    InspectEngineFuncPtr Callback; 

    struct {
        InspectionBufferGetDataPtr GetData; /* 获取数据, "http_uri", detect-http-uri.c/GetData() */
        InspectEngineFuncPtr2 Callback;     /* 检测函数, "http_uri", DetectEngineInspectBufferGeneric() */
        /** pointer to the transforms in the 'DetectBuffer entry for this list */
        const DetectEngineTransforms *transforms;  /* 检测数据的修饰操作, 如 DETECT_TRANSFORM_STRIP_WHITESPACE */
    } v2;

    SigMatchData *smd;        /* 对应的匹配链表 */

    struct DetectEngineAppInspectionEngine_ *next;
} DetectEngineAppInspectionEngine;

typedef struct DetectBufferType_ {
    const char *string; /* 检测类型，如http_uri */
    const char *description;   /* 描述性字符串, 如"http request uri" */
    int id;             /* 检测类型ID, 如 g_http_uri_buffer_id; 由 g_buffer_type_id 递增控制ID值, 位于 DETECT_SM_LIST_DYNAMIC_START 之后 */
    int parent_id;      /* 注册"检测类型+转换"时, 对应"检测类型->id" */
    bool mpm;                  /* 是否支持多模引擎 */
    bool packet;               /* 是否支持报文检测 *< compat to packet matches */
    bool supports_transforms;              /* 是否定义了转换, 如去掉空字符 DETECT_TRANSFORM_STRIP_WHITESPACE */
    void (*SetupCallback)(const struct DetectEngineCtx_ *, struct Signature_ *); /* "http_uri" -> DetectHttpUriSetupCallback() */
    bool (*ValidateCallback)(const struct Signature_ *, const char **sigerror);  /* "http_uri" -> DetectHttpUriValidateCallback() */
    DetectEngineTransforms transforms;     /* 转变描述数组 */
} DetectBufferType;                   /* 注册的内容检测关键字, 如"http_uri" */

struct DetectEnginePktInspectionEngine;

/**
 *  \param alert_flags[out] for setting PACKET_ALERT_FLAG_*
 */
typedef int (*InspectionBufferPktInspectFunc)(
        struct DetectEngineThreadCtx_ *,
        const struct DetectEnginePktInspectionEngine *engine,
        const struct Signature_ *s,
        Packet *p, uint8_t *alert_flags);

/** callback for getting the buffer we need to prefilter/inspect */
typedef InspectionBuffer *(*InspectionBufferGetPktDataPtr)(
        struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms,
        Packet *p, const int list_id);

typedef struct DetectEnginePktInspectionEngine {
    SigMatchData *smd;
    uint16_t mpm:1;
    uint16_t sm_list:15;
    struct {
        InspectionBufferGetPktDataPtr GetData;
        InspectionBufferPktInspectFunc Callback;
        /** pointer to the transforms in the 'DetectBuffer entry for this list */
        const DetectEngineTransforms *transforms;
    } v1;
    struct DetectEnginePktInspectionEngine *next;
} DetectEnginePktInspectionEngine;

#ifdef UNITTESTS
#define sm_lists init_data->smlists
#define sm_lists_tail init_data->smlists_tail
#endif

typedef struct SignatureInitData_ {
    /** Number of sigmatches. Used for assigning SigMatch::idx */
    uint16_t sm_cnt;              /* ->smlists和->smlists_tail维护的链表长度 */

    /** option was prefixed with '!'. Only set for sigmatches that
     *  have the SIGMATCH_HANDLE_NEGATION flag set. */
    bool negated;                 /* 规则选项前携带了"!" */

    /* track if we saw any negation in the addresses. If so, we
     * skip it for ip-only */
    bool src_contains_negation;   /* 规则的地址列表中是否包含"!" */
    bool dst_contains_negation;

    /* used to hold flags that are used during init */
    uint32_t init_flags;    /* SIG_FLAG_INIT_BIDIREC */
    /* coccinelle: SignatureInitData:init_flags:SIG_FLAG_INIT_ */

    /* used at init to determine max dsize */
    SigMatch *dsize_sm;     /* DetectDsizeData, dsize/DETECT_DSIZE 关键字, 设定了检测长度的匹配 */

    /* the fast pattern added from this signature */
    SigMatch *mpm_sm;       /* DetectContentData, 规则匹配列表支持fast pattern的匹配（且强度最高） */
    /* used to speed up init of prefilter */
    SigMatch *prefilter_sm; /* prefilter关键字对应的匹配 */

    /* SigMatch list used for adding content and friends. E.g. file_data; */
    int list;               /* 用于内容匹配的->smlists[]索引, 如 DETECT_SM_LIST_PMATCH/"http.uri"/"tcp.hdr" */
    bool list_set;          /* 便于向此匹配添加修改关键词(to_md5/DETECT_TRANSFORM_MD5) */

    DetectEngineTransforms transforms;/* 记录内容转换, 如to_md5/DETECT_TRANSFORM_MD5 */

    /** score to influence rule grouping. A higher value leads to a higher
     *  likelihood of a rulegroup with this sig ending up as a contained
     *  group. *//* 为后续构建规则组服务：分越高越容易成组 */
    int whitelist;                    /* 设置过程参考 RuleSetWhitelist() */

    /** address settings for this signature */
    const DetectAddressHead *src, *dst;   /* 规则的源/目的IP信息 */

    int prefilter_list;               /* */

    uint32_t smlists_array_size;      /* 注册的检测类型数, g_buffer_type_id */
    /* holds all sm lists */
    struct SigMatch_ **smlists;       /* 匹配环境(上下文)列表，指向非循环双链表的首元素 */
    /* holds all sm lists' tails */   /* 解析配置规则的option部分得到 */
    struct SigMatch_ **smlists_tail;  /* 指向非循环双链表的尾元素 */
} SignatureInitData;

/** \brief Signature container *//* 规则数据结构 */
typedef struct Signature_ {
    uint32_t flags;      /* SIG_FLAG_REQUIRE_PACKET, SIG_MASK_REQUIRE_PAYLOAD */
    /* coccinelle: Signature:flags:SIG_FLAG_ */

    AppProto alproto;    /* 检测协议(L7) */

    uint16_t dsize_low;  /* 设定的报文内容检测范围, DetectDsizeData, ->init_data->dsize_sm->ctx */
    uint16_t dsize_high;

    SignatureMask mask;  /* SIG_MASK_REQUIRE_DCERPC */
    SigIntId num;        /* 内部ID, 由 DetectEngineCtx->signum 递增得到; 按优先级排序后, 可作为优先级顺序 */

    /** inline -- action */
    uint8_t action;      /* 规则动作, ACTION_ALERT */
    uint8_t file_flags;

    /** addresses, ports and proto this sig matches on */
    DetectProto proto;   /* 检测协议(L3-L4)集, IPPROTO_TCP等的bit位表示 */

    /** classification id **/
    uint16_t class_id;   /* 赋值 SCClassConfClasstype->classtype_id */

    /** ipv4 match arrays */
    uint16_t addr_dst_match4_cnt;
    uint16_t addr_src_match4_cnt;
    uint16_t addr_dst_match6_cnt;
    uint16_t addr_src_match6_cnt;
    DetectMatchAddressIPv4 *addr_dst_match4;  /* 用于耗时匹配前的快速IP匹配 */
    DetectMatchAddressIPv4 *addr_src_match4;  /* 将->init_data->src->ipv4_head 变更为此处的数组 */
    /** ipv6 match arrays */
    DetectMatchAddressIPv6 *addr_dst_match6;
    DetectMatchAddressIPv6 *addr_src_match6;

    uint32_t id;    /* 特征ID，对应sid关键字 */
    uint32_t gid;   /* 默认值 1, generator id */
    uint32_t rev;   /* 版本号，对应rev关键字 */
    int prio;       /* 优先级，默认3; 可继承 SCClassConfClasstype->priority */

    /** port settings for this signature */
    DetectPort *sp, *dp;    /* 规则的五元组端口信息 */

#ifdef PROFILING
    uint16_t profiling_id;
#endif

    /** netblocks and hosts specified at the sid, in CIDR format */
    IPOnlyCIDRItem *CidrSrc, *CidrDst;        /* 临时变量，存放规则IP地址信息；当 SIG_FLAG_IPONLY 时, 加速匹配 */
    /* 本规则匹配检测引擎列表, 包括 >DETECT_SM_LIST_DYNAMIC_START/自注册, DETECT_SM_LIST_MATCH, DETECT_SM_LIST_PMATCH */
    DetectEngineAppInspectionEngine *app_inspect;  /* 应用引擎, 来自 g_app_inspect_engines */
    DetectEnginePktInspectionEngine *pkt_inspect;  /* 逐包报文引擎(prefilter多模式匹配在前), 来自 g_pkt_inspect_engines */

    /* Matching structures for the built-ins. The others are in
     * their inspect engines. *//* 内置类型的检测引擎, <DETECT_SM_LIST_MAX */
    SigMatchData *sm_arrays[DETECT_SM_LIST_MAX];

    /* memory is still owned by the sm_lists/sm_arrays entry */
    const struct DetectFilestoreData_ *filestore_ctx;

    char *msg;                   /* 来自msg关键字 */

    /** classification message */
    char *class_msg;             /* 赋值 SCClassConfClasstype->classtype_desc */
    /** Reference */
    DetectReference *references; /* DetectReference 链表, 对应"reference"配置关键字 */
    /** Metadata */
    DetectMetadataHead *metadata;

    char *sig_str;               /* 原配置规则字符串, 解析它得到此结构 */

    SignatureInitData *init_data;/* 检测相关的数据 */

    /** ptr to the next sig in the list */
    struct Signature_ *next;     /* 对于双向匹配，存储反向的Signature */
} Signature;

enum DetectBufferMpmType {
    DETECT_BUFFER_MPM_TYPE_PKT,  /* 针对报文的多模引擎 */
    DETECT_BUFFER_MPM_TYPE_APP,  /* 针对应用的多模引擎 */
    /* must be last */
    DETECT_BUFFER_MPM_TYPE_SIZE,
};

/* 支持多模式匹配的类型, 注册到 g_mpm_list[]/sm_fp_support_smlist_list, * \brief one time registration of keywords at start up */
typedef struct DetectBufferMpmRegistery_ {
    const char *name;  /* 如"http_uri" */
    char pname[32];    /* ->name的复制版本 */
    int direction;     /* SIG_FLAG_TOSERVER */
    int sm_list;       /* DetectBufferType->id */
    int priority;      /* 优先级 */
    int id;            /* 在此数组的索引, g_mpm_list[DETECT_BUFFER_MPM_TYPE_APP][] */
    enum DetectBufferMpmType type;  /* = DETECT_BUFFER_MPM_TYPE_APP */
    int sgh_mpm_context;            /* 共享: MPM_CTX_FACTORY_UNIQUE_CONTEXT; 独有: DetectEngineCtx->mpm_ctx_factory_container->items[].id */
                       /* 注册prefilter处理的函数, "http_uri" -> PrefilterGenericMpmRegister() */
    int (*PrefilterRegisterWithListId)(struct DetectEngineCtx_ *de_ctx,
            struct SigGroupHead_ *sgh, MpmCtx *mpm_ctx,
            const struct DetectBufferMpmRegistery_ *mpm_reg, int list_id);
    DetectEngineTransforms transforms;          /* 支持的内容修饰列表, 如 to_md5/DETECT_TRANSFORM_MD5 关键字 */

    union {
        /* app-layer matching: use if type == DETECT_BUFFER_MPM_TYPE_APP */
        struct {
            InspectionBufferGetDataPtr GetData; /* "http_uri" -> detect-http-uri.c/GetData() */
            AppProto alproto;                   /* "http_uri" -> ALPROTO_HTTP */
            int tx_min_progress;                /* "http_uri" -> HTP_REQUEST_LINE */
        } app_v2;

        /* pkt matching: use if type == DETECT_BUFFER_MPM_TYPE_PKT */
        struct {
            int (*PrefilterRegisterWithListId)(struct DetectEngineCtx_ *de_ctx,
                    struct SigGroupHead_ *sgh, MpmCtx *mpm_ctx,
                    const struct DetectBufferMpmRegistery_ *mpm_reg, int list_id);
            InspectionBufferGetPktDataPtr GetData;
        } pkt_v1;
    };

    struct DetectBufferMpmRegistery_ *next;
} DetectBufferMpmRegistery;

typedef struct DetectReplaceList_ {
    struct DetectContentData_ *cd;
    uint8_t *found;
    struct DetectReplaceList_ *next;
} DetectReplaceList;

/** only execute flowvar storage if rule matched */
#define DETECT_VAR_TYPE_FLOW_POSTMATCH      1
#define DETECT_VAR_TYPE_PKT_POSTMATCH       2

/** list for flowvar store candidates, to be stored from
 *  post-match function */
typedef struct DetectVarList_ {
    uint32_t idx;                       /**< flowvar name idx */
    uint16_t len;                       /**< data len */
    uint16_t key_len;
    int type;                           /**< type of store candidate POSTMATCH or ALWAYS */
    uint8_t *key;
    uint8_t *buffer;                    /**< alloc'd buffer, may be freed by
                                             post-match, post-non-match */
    struct DetectVarList_ *next;
} DetectVarList;

typedef struct DetectEngineIPOnlyThreadCtx_ {
    uint8_t *sig_match_array; /* bit array of sig nums */
    uint32_t sig_match_size;  /* size in bytes of the array */
} DetectEngineIPOnlyThreadCtx;   /* 记录IPonly引擎'源+目的IP地址'匹配到的规则集, 待进一步过'匹配' */

/** \brief IP only rules matching ctx. */
typedef struct DetectEngineIPOnlyCtx_ {
    /* lookup hashes */
    HashListTable *ht16_src, *ht16_dst;        /* */
    HashListTable *ht24_src, *ht24_dst;

    /* Lookup trees */       /* 键IP段 -> 数据 SigNumArray */
    SCRadixTree *tree_ipv4src, *tree_ipv4dst;  /* 构建自->ip_src/ip_dst */
    SCRadixTree *tree_ipv6src, *tree_ipv6dst;

    /* Used to build the radix trees */
    IPOnlyCIDRItem *ip_src, *ip_dst;           /* 汇集 Signature->CidrSrc/->CidrDst */

    /* counters */
    uint32_t a_src_uniq16, a_src_total16;
    uint32_t a_dst_uniq16, a_dst_total16;
    uint32_t a_src_uniq24, a_src_total24;
    uint32_t a_dst_uniq24, a_dst_total24;

    uint32_t max_idx;        /* 出现过的最大 Signature->num, 以减少后续遍历操作 */

    uint8_t *sig_init_array; /* 规则bit位数组，数量 = DetectEngineCtx->sig_array[], bit array of sig nums */
    uint32_t sig_init_size;  /* size in bytes of the array */

    /* number of sigs in this head */
    uint32_t sig_cnt;
    uint32_t *match_array;   /* 归属到本组的规则 */
} DetectEngineIPOnlyCtx;

typedef struct DetectEngineLookupFlow_ {
    DetectPort *tcp;      /* tcp协议规则组链表, 已按优先级排序 */
    DetectPort *udp;      /* udp协议规则组链表 */
    struct SigGroupHead_ *sgh[256];  /* 非TCP/UDP协议规则组 */
} DetectEngineLookupFlow;

#include "detect-threshold.h"

/** \brief threshold ctx */
typedef struct ThresholdCtx_    {
    SCMutex threshold_table_lock;                   /**< Mutex for hash table */

    /** to support rate_filter "by_rule" option */
    DetectThresholdEntry **th_entry;
    uint32_t th_size;
} ThresholdCtx;

typedef struct SigString_ {
    char *filename;
    char *sig_str;
    char *sig_error;
    int line;
    TAILQ_ENTRY(SigString_) next;
} SigString;

/** \brief Signature loader statistics */
typedef struct SigFileLoaderStat_ {
    TAILQ_HEAD(, SigString_) failed_sigs;
    int bad_files;
    int total_files;
    int good_sigs_total;
    int bad_sigs_total;
} SigFileLoaderStat;
/* 引擎全局关键字 */
typedef struct DetectEngineThreadKeywordCtxItem_ {
    void *(*InitFunc)(void *);   /* "http.header_names" -> HttpHeaderThreadDataInit() */
    void (*FreeFunc)(void *);    /* */
    void *data;         /* "http.header_names" -> detect-http-header-names.c/g_td_config */
    struct DetectEngineThreadKeywordCtxItem_ *next;
    int id;                      /* DetectEngineMasterCtx->keyword_list[]的索引 */
    const char *name;   /* 如"http.header_names"; keyword name, for error printing */
} DetectEngineThreadKeywordCtxItem;

enum DetectEnginePrefilterSetting
{
    DETECT_PREFILTER_MPM = 0,   /**< use only mpm / fast_pattern */
    DETECT_PREFILTER_AUTO = 1,  /**< use mpm + keyword prefilters */
};

enum DetectEngineType
{
    DETECT_ENGINE_TYPE_NORMAL = 0,
    DETECT_ENGINE_TYPE_DD_STUB = 1, /* delayed detect stub: can be reloaded */
    DETECT_ENGINE_TYPE_MT_STUB = 2, /* multi-tenant stub: cannot be reloaded */
    DETECT_ENGINE_TYPE_TENANT = 3,
};

/* Flow states:
 *  toserver
 *  toclient
 */
#define FLOW_STATES 2

/** \brief main detection engine ctx *//* 检测引擎信息结构 */
typedef struct DetectEngineCtx_ {
    uint8_t flags;
    int failure_fatal;            /* 解析失败，是否强制进程退出？ */

    int tenant_id;

    Signature *sig_list;          /* 检测规则列表，<TK!!!>已按优先级排序 */
    uint32_t sig_cnt;             /* 规则数量, = ->signum */

    /* version of the srep data */
    uint32_t srep_version;

    /* reputation for netblocks */
    SRepCIDRTree *srepCIDR_ctx;   /* IP信誉库 */

    Signature **sig_array;        /* 存放所有规则, ->sig_list, 以加速访问 */
    uint32_t sig_array_size;      /* 占用内存大小, size in bytes */
    uint32_t sig_array_len;       /* 数组大小, = ->signum; size in array members */

    uint32_t signum;              /* 解析时逐条++, 得到的检测规则数量; 按优先级排序后, 重新计数得到规则数量 */

    /** Maximum value of all our sgh's non_mpm_store_cnt setting,
     *  used to alloc det_ctx::non_mpm_id_array */
    uint32_t non_pf_store_cnt_max;/* 规则组中非prefilter的Signature最大数量 */

    /* used by the signature ordering module */    /* 由 SCSigRegisterSignatureOrderingFuncs() 注册 */
    struct SCSigOrderFunc_ *sc_sig_order_funcs;    /* 规则处理函数列表，按优先级排列; 排序完毕即释放 */

    /* hash table used for holding the classification config info *//* <TK!!!>0索引留给非配置文件，解析规则时添加  */
    HashTable *class_conf_ht;                      /* 解析结果, SCClassConfClasstype, /etc/suricata/classification.config */
    /* hash table used for holding the reference config info */
    HashTable *reference_conf_ht;                  /* 解析结果, SCRConfReference, /etc/suricata/reference.config */

    /* main sigs */
    DetectEngineLookupFlow flow_gh[FLOW_STATES];   /* 基于端口的规则组，建立了 DetectPort -> Signature 之间的快速对应关系 */

    uint32_t gh_unique, gh_reuse;     /* SigGroupHead计数, ->sgh_array[]大小 */

    /* init phase vars */
    HashListTable *sgh_hash_table;    /* 临时 SigGroupHead 哈希表，用于去重 */

    HashListTable *mpm_hash_table;    /* MpmStore 哈希表, 比如prefilter的多模环境 */

    /* hash table used to cull out duplicate sigs */
    HashListTable *dup_sig_hash_table;/* 存放所有规则->sig_list，以检测重复 */

    DetectEngineIPOnlyCtx io_ctx;  /* IP Only规则组: IP地址 -> Signature */
    ThresholdCtx ths_ctx;          /* 支持threshold/"by_rule"流量过滤器 */

    uint16_t mpm_matcher;    /* 默认多模引擎类型, MPM_HS */
    uint16_t spm_matcher;    /* 默认单模引擎类型, SPM_HS */

    /* spm thread context prototype, built as spm matchers are constructed and
     * later used to construct thread context for each thread. */
    SpmGlobalThreadCtx *spm_global_thread_ctx;  /* 单模引擎全局上下文 */
                                                /* 用于构建各线程检测上下文 */
    /* Config options */
                             /* "detect.profile", 性能指标：高性能使用内存多; 指定的数字为组个数 */
    uint16_t max_uniq_toclient_groups;  /* 20 */  /* 低性能使用内存少；此选 */
    uint16_t max_uniq_toserver_groups;  /* 40 */  /* 项需要在性能和内存之间平衡 */

    /* specify the configuration for mpm context factory */
    uint8_t sgh_mpm_context; /* 多模匹配工厂模型, ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE, 来自配置文件detect.sgh-mpm-context */

    /* max flowbit id that is used */
    uint32_t max_fb_id;      /* 支持的flowbit规则数 */

    uint32_t max_fp_id;      /* 支持fast pattern且去重后的 SigMatch 个数 */

    MpmCtxFactoryContainer *mpm_ctx_factory_container;
                             /* 多模引擎工厂 */
    /* maximum recursion depth for content inspection */
    int inspection_recursion_limit;     /* 性能指标 - 迭代检测上限，3000 */

    /* conf parameter that limits the length of the http request body inspected */
    int hcbd_buffer_limit;
    /* conf parameter that limits the length of the http response body inspected */
    int hsbd_buffer_limit;

    /* array containing all sgh's in use so we can loop
     * through it in Stage4. */
    struct SigGroupHead_ **sgh_array;   /* 存储所有 SigGroupHead, 用于遍历 */
    uint32_t sgh_array_cnt;             /* 对应 ->sgh_hash_table */
    uint32_t sgh_array_size;

    int32_t sgh_mpm_context_proto_tcp_packet;   /* 非独享下, 多模引擎工厂, for 'tcp-packet'; = DetectEngineCtx->mpm_ctx_factory_container->items[]->id */
    int32_t sgh_mpm_context_proto_udp_packet;   /* for 'udp-packet' */
    int32_t sgh_mpm_context_proto_other_packet; /* for 'other-ip' */
    int32_t sgh_mpm_context_stream;             /* for 'tcp-stream' */

    /* the max local id used amongst all sigs */
    int32_t byte_extract_max_local_id;

    /** version of the detect engine. The version is incremented on reloads */
    uint32_t version;

    /** sgh for signatures that match against invalid packets. In those cases
     *  we can't lookup by proto, address, port as we don't have these */
    struct SigGroupHead_ *decoder_event_sgh;    /* 仅基于解析事件的组, 包含 SIG_FLAG_INIT_DEONLY 标识的规则 */

    /* Maximum size of the buffer for decoded base64 data. */
    uint32_t base64_decode_max_len;

    /** Store rule file and line so that parsers can use them in errors. */
    char *rule_file;        /* <解析过程中>规则文件名，suricata.rules */
    int rule_line;          /* <解析过程中>行号 */
    bool sigerror_silent;
    bool sigerror_ok;
    const char *sigerror;

    /** list of keywords that need thread local ctxs */
    DetectEngineThreadKeywordCtxItem *keyword_list;
    int keyword_id;

    struct {
        uint32_t content_limit;
        uint32_t content_inspect_min_size;
        uint32_t content_inspect_window;
    } filedata_config[ALPROTO_MAX];
    bool filedata_config_initialized;

#ifdef PROFILING
    struct SCProfileDetectCtx_ *profile_ctx;
    struct SCProfileKeywordDetectCtx_ *profile_keyword_ctx;
    struct SCProfilePrefilterDetectCtx_ *profile_prefilter_ctx;
    struct SCProfileKeywordDetectCtx_ **profile_keyword_ctx_per_list;
    struct SCProfileSghDetectCtx_ *profile_sgh_ctx;
    uint32_t profile_match_logging_threshold;
#endif
    uint32_t prefilter_maxid;       /* 最大的prefilter索引 */

    char config_prefix[64];         /* 每次重新加载引擎，都对应自己的前缀，用于寻找新版本suricata.yaml配置解析结果 */
                                    /* 如"multi-detect.%d.reload.%d" / "detect-engine-reloads.%d" */
    enum DetectEngineType type;     /* 检测引擎类型, DETECT_ENGINE_TYPE_NORMAL */

    /** how many de_ctx' are referencing this */
    uint32_t ref_cnt;
    /** list in master: either active or freelist */
    struct DetectEngineCtx_ *next;

    /** id of loader thread 'owning' this de_ctx */
    int loader_id;
    /* prefilter技术以加速规则匹配: 各规则选择比较独特的匹配项, 组成prefilter多模匹配 */
    /** are we using just mpm or also other prefilters *//* 以最少次数匹配到具体signature */
    enum DetectEnginePrefilterSetting prefilter_setting;
                                 /* 预检测仅使用mpm, DETECT_PREFILTER_MPM */
    HashListTable *dport_hash_table;  /* 临时hash表, DetectPort; 用于初始化流程 */

    DetectPort *tcp_whitelist;   /* 配置的端口, 可形成单独的组 */
    DetectPort *udp_whitelist;

    /** table for storing the string representation with the parsers result */
    HashListTable *address_table;/* 规则解析时，地址段及其解析结果，节省解析时间和空间 */

    /** table to store metadata keys and values */
    HashTable *metadata_table;

    DetectBufferType **buffer_type_map;  /* 注册的检测类型, 来自 g_buffer_type_hash 链表 */
    uint32_t buffer_type_map_elements;   /* 此处为数组, 可加速索引能力 */

    /* hash table with rule-time buffer registration. Start time registration
     * is in detect-engine.c::g_buffer_type_hash */
    HashListTable *buffer_type_hash;     /* 运行期间注册的检测类型 */
    int buffer_type_id;                  /* = g_buffer_type_id */

    /* list with app inspect engines. Both the start-time registered ones and
     * the rule-time registered ones. */
    DetectEngineAppInspectionEngine *app_inspect_engines; /* 用于单规则的检测引擎, 复制自 g_app_inspect_engines */
    DetectBufferMpmRegistery *app_mpms_list;  /* 用于prefilter的多模式引擎 */
    uint32_t app_mpms_list_cnt;               /* = g_mpm_list[DETECT_BUFFER_MPM_TYPE_APP] */
    DetectEnginePktInspectionEngine *pkt_inspect_engines; /* 用于单规则的检测引擎,  g_pkt_inspect_engines */
    DetectBufferMpmRegistery *pkt_mpms_list;  /* 用于prefilter的多模式引擎 */
    uint32_t pkt_mpms_list_cnt;               /* = g_mpm_list[DETECT_BUFFER_MPM_TYPE_PKT] */

    uint32_t prefilter_id;
    HashListTable *prefilter_hash_table; /* PrefilterStore, prefilter多模引擎哈希表, 记录prefilter引擎的种类 */

    /** time of last ruleset reload */
    struct timeval last_reload;          /* 规则加载后的时间 */

    /** signatures stats */
    SigFileLoaderStat sig_stat;          /* 规则文件解析统计结果 */

    /** per keyword flag indicating if a prefilter has been
     *  set for it. If true, the setup function will have to
     *  run. */                          /* 被关键字prefilter修饰的匹配类型 */
    bool sm_types_prefilter[DETECT_TBLSIZE];
    bool sm_types_silent_error[DETECT_TBLSIZE];

} DetectEngineCtx;

/* Engine groups profiles (low, medium, high, custom) */
enum {
    ENGINE_PROFILE_UNKNOWN,
    ENGINE_PROFILE_LOW,
    ENGINE_PROFILE_MEDIUM,    /* 中等, 性能级别影响基于端口的组的数量的多少 */
    ENGINE_PROFILE_HIGH,      /* 级别越高, 组上限越多, 匹配更快, 但消耗内存 */
    ENGINE_PROFILE_CUSTOM,    /* 越大 */
    ENGINE_PROFILE_MAX
};

/* Siggroup mpm context profile */
enum {
    ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL,
    ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE,  /* 规则组共享多模上下文, <默认值> */
    ENGINE_SGH_MPM_FACTORY_CONTEXT_AUTO
};

typedef struct HttpReassembledBody_ {
    const uint8_t *buffer;
    uint8_t *decompressed_buffer;
    uint32_t buffer_size;   /**< size of the buffer itself */
    uint32_t buffer_len;    /**< data len in the buffer */
    uint32_t decompressed_buffer_len;
    uint64_t offset;        /**< data offset */
} HttpReassembledBody;

#define DETECT_FILESTORE_MAX 15

typedef struct SignatureNonPrefilterStore_ {
    SigIntId id;           /* 规则ID, Signature->num */
    SignatureMask mask;    /* 需要的标识 */
    uint8_t alproto;       /* 应用协议 */
} SignatureNonPrefilterStore;

/** array of TX inspect rule candidates */
typedef struct RuleMatchCandidateTx {
    SigIntId id;            /**< internal signature id */
    uint32_t *flags;        /**< inspect flags ptr */
    union {
        struct {
            bool stream_stored;
            uint8_t stream_result;
        };
        uint32_t stream_reset;
    };

    const Signature *s;     /**< ptr to sig */
} RuleMatchCandidateTx;

/**
  * Detection engine thread data.
  */
typedef struct DetectEngineThreadCtx_ {
    /** \note multi-tenant hash lookup code from Detect() *depends*
     *        on this being the first member */
    uint32_t tenant_id;

    /** ticker that is incremented once per packet. */
    uint64_t ticker;             /* 逐包递增的计数 */

    /* the thread to which this detection engine thread belongs */
    ThreadVars *tv;

    /** Array of non-prefiltered sigs that need to be evaluated. Updated
     *  per packet based on the rule group and traffic properties. *//* 每报文更新 */
    SigIntId *non_pf_id_array;   /* 适用于当前流/报文的规则(非prefilter)，来自于 ->non_pf_store_ptr */
    uint32_t non_pf_id_cnt;      // size is cnt * sizeof(uint32_t)

    uint32_t mt_det_ctxs_cnt;
    struct DetectEngineThreadCtx_ **mt_det_ctxs;
    HashTable *mt_det_ctxs_hash;

    struct DetectEngineTenantMapping_ *tenant_array;
    uint32_t tenant_array_size;

    uint32_t (*TenantGetId)(const void *, const Packet *p);

    /* detection engine variables */

    uint64_t raw_stream_progress;       /* 负载检测时, 已经检测的数据的缓存偏移 */

    /** offset into the payload of the last match by:
     *  content, pcre, etc */
    uint32_t buffer_offset;             /* 上次匹配结果尾对应的偏移, 以应对within/distance等相对位置关键字 */
    /* used by pcre match function alone */
    uint32_t pcre_match_start_offset;

    /* counter for the filestore array below -- up here for cache reasons. */
    uint16_t filestore_cnt;             /* ->filestore[]大小, 因为cache原因放置于此 */
                                        /* 逐包清空 */
    /** id for alert counter */
    uint16_t counter_alerts;            /* */
#ifdef PROFILING
    uint16_t counter_mpm_list;
    uint16_t counter_nonmpm_list;
    uint16_t counter_fnonmpm_list;
    uint16_t counter_match_list;
#endif

    int inspect_list; /**< list we're currently inspecting, DETECT_SM_LIST_* */

    struct {
        InspectionBuffer *buffers;      /* 待检测的缓存 */
        uint32_t buffers_size;          /* 缓存种类, sizeof(buffers[])/sizeof(buffers[0]), = DetectEngineCtx->buffer_type_id  */
        uint32_t to_clear_idx;
        uint32_t *to_clear_queue;       /* 待清理的->buffers[]的索引数组 */
    } inspect;      /* 检测类型对应的临时缓存 */

    struct {
        /** inspection buffers for more complex case. As we can inspect multiple
         *  buffers in parallel, we need this extra wrapper struct */
        InspectionBufferMultipleForList *buffers;
        uint32_t buffers_size;                      /**< in number of elements */
        uint32_t to_clear_idx;
        uint32_t *to_clear_queue;
    } multi_inspect;/* 支持并行检测 */

    /* used to discontinue any more matching */
    uint16_t discontinue_matching;      /* */
    uint16_t flags;

    /* bool: if tx_id is set, this is 1, otherwise 0 */
    uint16_t tx_id_set;            /* tx_id是否已经设定/有效? */
    /** ID of the transaction currently being inspected. */
    uint64_t tx_id;                /* 当前正检测的事务ID */
    Packet *p;                     /* 当前正处理的报文 */

    SC_ATOMIC_DECLARE(int, so_far_used_by_detect);  /* 此线程检测结构, 是否被使用过 */

    /* holds the current recursion depth on content inspection */
    int inspection_recursion_counter;

    /** array of signature pointers we're going to inspect in the detection
     *  loop. */
    Signature **match_array;       /* prefilter/non-prefilter匹配到的规则，待逐个匹配检测 */
    /** size of the array in items (mem size if * sizeof(Signature *)
     *  Only used during initialization. */
    uint32_t match_array_len;
    /** size in use */
    SigIntId match_array_cnt;

    RuleMatchCandidateTx *tx_candidates;
    uint32_t tx_candidates_size;   /* 事务prefilter引擎匹配到的规则列表 + 前置未过匹配的已匹配规则 + 旧候选规则，= match_array_len */

    SignatureNonPrefilterStore *non_pf_store_ptr;
    uint32_t non_pf_store_cnt;     /* non-prefilter列表, 赋值为 SigGroupHead->non_pf_syn_store_array/->non_pf_other_store_array */

    /** pointer to the current mpm ctx that is stored
     *  in a rule group head -- can be either a content
     *  or uricontent ctx. */      /* 多模匹配环境 */
    MpmThreadCtx mtc;   /**< thread ctx for the mpm */
    MpmThreadCtx mtcu;  /**< thread ctx for uricontent mpm */
    MpmThreadCtx mtcs;  /**< thread ctx for stream mpm */
    PrefilterRuleStore pmq;        /* prefilter引擎匹配暂存结果, 因为有多种prefilter匹配引擎 */

    /** SPM thread context used for scanning. This has been cloned from the
     * prototype held by DetectEngineCtx. */
    SpmThreadCtx *spm_thread_ctx;  /* 单模式匹配环境 */

    /** ip only rules ctx */
    DetectEngineIPOnlyThreadCtx io_ctx;   /* 记录IPonly检测结果 */

    /* byte_* values */
    uint64_t *byte_values;

    /* string to replace */
    DetectReplaceList *replist;
    /* vars to store in post match function */
    DetectVarList *varlist;

    /* Array in which the filestore keyword stores file id and tx id. If the
     * full signature matches, these are processed by a post-match filestore
     * function to finalize the store. */
    struct {                           /* 匹配到‘filestore’规则后, 存储文件信息 */
        uint32_t file_id; /* File->file_track_id */
        uint64_t tx_id;   /* ->tx_id */
    } filestore[DETECT_FILESTORE_MAX];

    DetectEngineCtx *de_ctx;           /* 当前的检测环境 */
    /** store for keyword contexts that need a per thread storage. Per de_ctx. */
    void **keyword_ctxs_array;         /* */
    int keyword_ctxs_size;
    /** store for keyword contexts that need a per thread storage. Global. */
    int global_keyword_ctxs_size;
    void **global_keyword_ctxs_array;

    uint8_t *base64_decoded;           /* */
    int base64_decoded_len;
    int base64_decoded_len_max;

    AppLayerDecoderEvents *decoder_events;
    uint16_t events;

#ifdef DEBUG
    uint64_t pkt_stream_add_cnt;
    uint64_t payload_mpm_cnt;
    uint64_t payload_mpm_size;
    uint64_t stream_mpm_cnt;
    uint64_t stream_mpm_size;
    uint64_t payload_persig_cnt;
    uint64_t payload_persig_size;
    uint64_t stream_persig_cnt;
    uint64_t stream_persig_size;
#endif
#ifdef PROFILING
    struct SCProfileData_ *rule_perf_data;
    int rule_perf_data_size;
    struct SCProfileKeywordData_ *keyword_perf_data;
    struct SCProfileKeywordData_ **keyword_perf_data_per_list;
    int keyword_perf_list; /**< list we're currently inspecting, DETECT_SM_LIST_* */
    struct SCProfileSghData_ *sgh_perf_data;

    struct SCProfilePrefilterData_ *prefilter_perf_data;
    int prefilter_perf_size;
#endif
} DetectEngineThreadCtx;   /* 存放检测所需的临时信息 */

/** \brief element in sigmatch type table.
 */
typedef struct SigTableElmt_ {
    /** Packet match function pointer */
    int (*Match)(DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);

    /** AppLayer TX match function pointer */
    int (*AppLayerTxMatch)(DetectEngineThreadCtx *, Flow *,
            uint8_t flags, void *alstate, void *txv,
            const Signature *, const SigMatchCtx *);

    /** File match function  pointer */
    int (*FileMatch)(DetectEngineThreadCtx *,
        Flow *,                     /**< *LOCKED* flow */
        uint8_t flags, File *, const Signature *, const SigMatchCtx *);

    /** InspectionBuffer transformation callback */
    void (*Transform)(InspectionBuffer *, void *context);
    bool (*TransformValidate)(const uint8_t *content, uint16_t content_len, void *context);

    /** keyword setup function pointer */
    int (*Setup)(DetectEngineCtx *, Signature *, const char *);

    bool (*SupportsPrefilter)(const Signature *s);  /* 判断是否支持prefilter过滤? 如 DETECT_TCPMSS/PrefilterTcpmssIsPrefilterable() */
    int (*SetupPrefilter)(DetectEngineCtx *de_ctx, struct SigGroupHead_ *sgh); /* DETECT_TCPMSS/PrefilterSetupTcpmss() */

    void (*Free)(DetectEngineCtx *, void *);
#ifdef UNITTESTS
    void (*RegisterTests)(void);
#endif
    uint16_t flags;
    /* coccinelle: SigTableElmt:flags:SIGMATCH_ */

    /** better keyword to replace the current one */
    uint16_t alternative; /* 可被替换的关键字别名 */

    const char *name;     /* 关键字名, 如http_uri *< keyword name alias */
    const char *alias;    /* 别名 *< name alias */
    const char *desc;     /* 描述信息 */
    const char *url;      /*  */

} SigTableElmt; /* 规则关键字描述结构 */

/* event code */
enum {
#ifdef UNITTESTS
    DET_CTX_EVENT_TEST,
#endif
    FILE_DECODER_EVENT_NO_MEM,
    FILE_DECODER_EVENT_INVALID_SWF_LENGTH,
    FILE_DECODER_EVENT_INVALID_SWF_VERSION,
    FILE_DECODER_EVENT_Z_DATA_ERROR,
    FILE_DECODER_EVENT_Z_STREAM_ERROR,
    FILE_DECODER_EVENT_Z_BUF_ERROR,
    FILE_DECODER_EVENT_Z_UNKNOWN_ERROR,
    FILE_DECODER_EVENT_LZMA_DECODER_ERROR,
    FILE_DECODER_EVENT_LZMA_MEMLIMIT_ERROR,
    FILE_DECODER_EVENT_LZMA_OPTIONS_ERROR,
    FILE_DECODER_EVENT_LZMA_FORMAT_ERROR,
    FILE_DECODER_EVENT_LZMA_DATA_ERROR,
    FILE_DECODER_EVENT_LZMA_BUF_ERROR,
    FILE_DECODER_EVENT_LZMA_UNKNOWN_ERROR,
};

#define SIG_GROUP_HEAD_HAVERAWSTREAM    BIT_U32(0)
#ifdef HAVE_MAGIC
#define SIG_GROUP_HEAD_HAVEFILEMAGIC    BIT_U32(20)
#endif
#define SIG_GROUP_HEAD_HAVEFILEMD5      BIT_U32(21)
#define SIG_GROUP_HEAD_HAVEFILESIZE     BIT_U32(22)
#define SIG_GROUP_HEAD_HAVEFILESHA1     BIT_U32(23)
#define SIG_GROUP_HEAD_HAVEFILESHA256   BIT_U32(24)

enum MpmBuiltinBuffers {
    MPMB_TCP_PKT_TS,
    MPMB_TCP_PKT_TC,
    MPMB_TCP_STREAM_TS,
    MPMB_TCP_STREAM_TC,
    MPMB_UDP_TS,
    MPMB_UDP_TC,
    MPMB_OTHERIP,
    MPMB_MAX,
};

typedef struct MpmStore_ {
    uint8_t *sid_array;        /* 对应的规则组, Signature */
    uint32_t sid_array_size;

    int direction;             /* SIG_FLAG_TOSERVER */
    enum MpmBuiltinBuffers buffer;  /* 类型 MPMB_TCP_PKT_TS */
    int sm_list;               /* DETECT_SM_LIST_PMATCH */
    int32_t sgh_mpm_context;   /* 多模匹配共享环境ID, -1(非共享)/DetectEngineCtx->sgh_mpm_context_proto_tcp_packet */

    MpmCtx *mpm_ctx;           /* 多模上下文, MPM_HS - SCHSCtx, 由->sid_array[] 构建 */

} MpmStore;

typedef struct PrefilterEngineList_ {
    uint16_t id;             /* 在规则组中的索引, SigGroupHead->init->payload_engines/pkt_engines 链表中顺序 */

    /** App Proto this engine applies to: only used with Tx Engines */
    AppProto alproto;
    /** Minimal Tx progress we need before running the engine. Only used
     *  with Tx Engine */
    int tx_min_progress;

    /** Context for matching. Might be MpmCtx for MPM engines, other ctx'
     *  for other engines. *//* DETECT_ACK -> PrefilterPacketHeaderCtx/PrefilterPacketAckMatch() */
    void *pectx;             /* 多模匹配 - MpmCtx *//* Txengine - PrefilterMpmCtx */
    /* "payload" - PrefilterPktPayload() *//* "stream" - PrefilterPktStream() */
    void (*Prefilter)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx);
    void (*PrefilterTx)(DetectEngineThreadCtx *det_ctx, const void *pectx,
            Packet *p, Flow *f, void *tx,
            const uint64_t idx, const uint8_t flags);

    struct PrefilterEngineList_ *next;

    /** Free function for pectx data. If NULL the memory is not freed. */
    void (*Free)(void *pectx);

    const char *name;        /* DETECT_ACK -> "ack" */
    /* global id for this prefilter */
    uint32_t gid;            /* 全局索引, = PrefilterStore->id */
} PrefilterEngineList;

typedef struct PrefilterEngine_ {
    uint16_t local_id;    /* 本类型prefilter引擎链表中的位置, 排序ID */

    /** App Proto this engine applies to: only used with Tx Engines */
    AppProto alproto;     /* 适用的应用协议 */
    /** Minimal Tx progress we need before running the engine. Only used
     *  with Tx Engine */
    int tx_min_progress;  /* 运行引擎的起始阶段 */

    /** Context for matching. Might be MpmCtx for MPM engines, other ctx'
     *  for other engines. */
    void *pectx;          /* 匹配内容的引擎, 如MPM等 */

    union {               /* 指定的引擎回调函数 */
        void (*Prefilter)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx);
        void (*PrefilterTx)(DetectEngineThreadCtx *det_ctx, const void *pectx,
                Packet *p, Flow *f, void *tx,
                const uint64_t idx, const uint8_t flags);
    } cb;

    /* global id for this prefilter */
    uint32_t gid;         /* = PrefilterEngineList->gid */
    int is_last;          /* 标识链表结束 */
} PrefilterEngine;

typedef struct SigGroupHeadInitData_ {
    MpmStore mpm_store[MPMB_MAX];

    uint8_t *sig_array;  /* 包含的规则的bit位数组 */
    uint32_t sig_size;

    uint8_t protos[256]; /* 对应的协议 */
    uint32_t direction;  /* 对应的数据流方向, SIG_FLAG_TOSERVER, SIG_FLAG_TOCLIENT or both */
    int whitelist;       /* 值越大，越容易加入组 */

    MpmCtx **app_mpms;   /* 存储->tx_engines对应的引擎上下文; 来自 DetectEngineCtx->app_mpms_list */
    MpmCtx **pkt_mpms;   /*                                   来自 DetectEngineCtx->pkt_mpms_list */

    PrefilterEngineList *pkt_engines;     /* prefilter多模式引擎: "prefilter"关键字 + 基于报文的动态注册类型 */
    PrefilterEngineList *payload_engines; /*                    : "fast_patten"关键字 */
    PrefilterEngineList *tx_engines;      /* 动态检测类型对应的事务prefilter多模引擎 */

    /* port ptr */
    struct DetectPort_ *port;
} SigGroupHeadInitData;

/** \brief Container for matching data for a signature group */
typedef struct SigGroupHead_ {
    uint32_t flags;       /* SIG_GROUP_HEAD_HAVEFILEMAGIC */
    /* coccinelle: SigGroupHead:flags:SIG_GROUP_HEAD_ */

    /* number of sigs in this head */
    SigIntId sig_cnt;     /* 包含的规则数, = ->init->sig_array[]有效bit位数 */

    /* non prefilter list excluding SYN rules */
    uint32_t non_pf_other_store_cnt;   /* 非prefilter多模引擎 */
    uint32_t non_pf_syn_store_cnt;
    SignatureNonPrefilterStore *non_pf_other_store_array; // size is non_mpm_store_cnt * sizeof(SignatureNonPrefilterStore)
    /* non mpm list including SYN rules */
    SignatureNonPrefilterStore *non_pf_syn_store_array; // size is non_mpm_syn_store_cnt * sizeof(SignatureNonPrefilterStore)

    /** the number of signatures in this sgh that have the filestore keyword
     *  set. */
    uint16_t filestore_cnt;     /* 设置了 SIG_FLAG_FILESTORE 标识的signature数 */

    uint32_t id;                /* 在 DetectEngineCtx->sgh_array[] 中的索引 */

    PrefilterEngine *pkt_engines;      /* 拷贝自->init->pkt_engines */
    PrefilterEngine *payload_engines;  /*             ->payload_engines */
    PrefilterEngine *tx_engines;       /*             ->tx_engines */

    /** Array with sig ptrs... size is sig_cnt * sizeof(Signature *) */
    Signature **match_array;    /* 大小为->sig_cnt, 存储本组包含的规则 */

    /* ptr to our init data we only use at... init :) */
    SigGroupHeadInitData *init; /* 初始化期间使用的数据 */

} SigGroupHead;

/** sigmatch has no options, so the parser shouldn't expect any */
#define SIGMATCH_NOOPT                  BIT_U16(0)   /* 关键字没有配置项, 如prefilter等 */
/** sigmatch is compatible with a ip only rule */
#define SIGMATCH_IPONLY_COMPAT          BIT_U16(1)   /* 和IPONLY兼容, 如tag关键字 */
/** sigmatch is compatible with a decode event only rule */
#define SIGMATCH_DEONLY_COMPAT          BIT_U16(2)
/**< Flag to indicate that the signature is not built-in */
#define SIGMATCH_NOT_BUILT              BIT_U16(3)
/** sigmatch may have options, so the parser should be ready to
 *  deal with both cases */
#define SIGMATCH_OPTIONAL_OPT           BIT_U16(4)
/** input may be wrapped in double quotes. They will be stripped before
 *  input data is passed to keyword parser */
#define SIGMATCH_QUOTES_OPTIONAL        BIT_U16(5)
/** input MUST be wrapped in double quotes. They will be stripped before
 *  input data is passed to keyword parser. Missing double quotes lead to
 *  error and signature invalidation. */
#define SIGMATCH_QUOTES_MANDATORY       BIT_U16(6)   /* 输入必须被双引号包围 */
/** negation parsing is handled by the rule parser. Signature::init_data::negated
 *  will be set to true or false prior to calling the keyword parser. Exclamation
 *  mark is stripped from the input to the keyword parser. */
#define SIGMATCH_HANDLE_NEGATION        BIT_U16(7)
/* 此关键字为内容修饰符, 如http_uri, * keyword is a content modifier */
#define SIGMATCH_INFO_CONTENT_MODIFIER  BIT_U16(8)
/** keyword is a sticky buffer */
#define SIGMATCH_INFO_STICKY_BUFFER     BIT_U16(9)   /* sticky buffer, 如http.uri/tcp.hdr */
/** keyword is deprecated: used to suggest an alternative */
#define SIGMATCH_INFO_DEPRECATED        BIT_U16(10)
/** 严格解析规则, 出错就退出程序; strict parsing is enabled */
#define SIGMATCH_STRICT_PARSING         BIT_U16(11)

enum DetectEngineTenantSelectors
{
    TENANT_SELECTOR_UNKNOWN = 0,    /**< not set */
    TENANT_SELECTOR_DIRECT,         /**< method provides direct tenant id */
    TENANT_SELECTOR_VLAN,           /**< map vlan to tenant id */
    TENANT_SELECTOR_LIVEDEV,        /**< map livedev to tenant id */
};

typedef struct DetectEngineTenantMapping_ {
    uint32_t tenant_id;

    /* traffic id that maps to the tenant id */
    uint32_t traffic_id;

    struct DetectEngineTenantMapping_ *next;
} DetectEngineTenantMapping;

typedef struct DetectEngineMasterCtx_ {
    SCMutex lock;

    /** enable multi tenant mode */
    int multi_tenant_enabled;    /* 是否支持多租户 */

    /** version, incremented after each 'apply to threads' */
    uint32_t version;            /* 版本号，初始值99，每次加载规则后++ */

    /** list of active detection engines. This list is used to generate the
     *  threads det_ctx's */
    DetectEngineCtx *list;       /* 激活的检测引擎 */

    /** free list, containing detection engines that will be removed but may
     *  still be referenced by det_ctx's. Freed as soon as all references are
     *  gone. */
    DetectEngineCtx *free_list;  /* 待释放的检测引擎 */

    enum DetectEngineTenantSelectors tenant_selector;

    /** list of tenant mappings. Updated under lock. Used to generate lookup
     *  structures. */
    DetectEngineTenantMapping *tenant_mapping_list;

    /** list of keywords that need thread local ctxs,
     *  only updated by keyword registration at start up. Not
     *  covered by the lock. */  /* 全局关键字, */
    DetectEngineThreadKeywordCtxItem *keyword_list;
    int keyword_id;              /* ->keyword_list[]长度 */
} DetectEngineMasterCtx;

/* Table with all SigMatch registrations */
extern SigTableElmt sigmatch_table[DETECT_TBLSIZE];

/** Remember to add the options in SignatureIsIPOnly() at detect.c otherwise it wont be part of a signature group */

/* detection api */
TmEcode Detect(ThreadVars *tv, Packet *p, void *data);

SigMatch *SigMatchAlloc(void);
Signature *SigFindSignatureBySidGid(DetectEngineCtx *, uint32_t, uint32_t);
void SigMatchSignaturesBuildMatchArray(DetectEngineThreadCtx *,
                                       Packet *, SignatureMask,
                                       uint16_t);
void SigMatchFree(DetectEngineCtx *, SigMatch *sm);

void SigRegisterTests(void);
void TmModuleDetectRegister (void);

void SigAddressPrepareBidirectionals (DetectEngineCtx *);

void DisableDetectFlowFileFlags(Flow *f);
char *DetectLoadCompleteSigPath(const DetectEngineCtx *, const char *sig_file);
int SigLoadSignatures (DetectEngineCtx *, char *, int);
void SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx,
                       DetectEngineThreadCtx *det_ctx, Packet *p);

int SignatureIsIPOnly(DetectEngineCtx *de_ctx, const Signature *s);
const SigGroupHead *SigMatchSignaturesGetSgh(const DetectEngineCtx *de_ctx, const Packet *p);

Signature *DetectGetTagSignature(void);


int DetectUnregisterThreadCtxFuncs(DetectEngineCtx *, DetectEngineThreadCtx *,void *data, const char *name);
int DetectRegisterThreadCtxFuncs(DetectEngineCtx *, const char *name, void *(*InitFunc)(void *), void *data, void (*FreeFunc)(void *), int);
void *DetectThreadCtxGetKeywordThreadCtx(DetectEngineThreadCtx *, int);

void DetectSignatureApplyActions(Packet *p, const Signature *s, const uint8_t);

void RuleMatchCandidateTxArrayInit(DetectEngineThreadCtx *det_ctx, uint32_t size);
void RuleMatchCandidateTxArrayFree(DetectEngineThreadCtx *det_ctx);

int DetectFlowbitsAnalyze(DetectEngineCtx *de_ctx);

int DetectMetadataHashInit(DetectEngineCtx *de_ctx);
void DetectMetadataHashFree(DetectEngineCtx *de_ctx);

/* events */
void DetectEngineSetEvent(DetectEngineThreadCtx *det_ctx, uint8_t e);
AppLayerDecoderEvents *DetectEngineGetEvents(DetectEngineThreadCtx *det_ctx);
int DetectEngineGetEventInfo(const char *event_name, int *event_id,
                             AppLayerEventType *event_type);

#include "detect-engine-build.h"
#include "detect-engine-register.h"

#endif /* __DETECT_H__ */

