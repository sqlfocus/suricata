/* Copyright (C) 2007-2016 Open Information Security Foundation
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

#ifndef __DETECT_ENGINE_PREFILTER_COMMON_H__
#define __DETECT_ENGINE_PREFILTER_COMMON_H__

typedef union {
    uint8_t u8[16];
    uint16_t u16[8];
    uint32_t u32[4];
    uint64_t u64[2];
} PrefilterPacketHeaderValue;  /* prefilter匹配所需要的通用数据结构 */

#define PREFILTER_EXTRA_MATCH_UNUSED  0
#define PREFILTER_EXTRA_MATCH_ALPROTO 1
#define PREFILTER_EXTRA_MATCH_SRCPORT 2
#define PREFILTER_EXTRA_MATCH_DSTPORT 3

typedef struct PrefilterPacketHeaderCtx_ {
    PrefilterPacketHeaderValue v1;  /* 匹配信息 */

    uint16_t type;      /* 额外匹配类型, 如 PREFILTER_EXTRA_MATCH_ALPROTO */
    uint16_t value;     /* 额外匹配值, 如 ALPROTO_UNKNOWN */

    /** rules to add when the flags are present */
    uint32_t sigs_cnt;              /* 复用此结构的规则 */
    SigIntId *sigs_array;
} PrefilterPacketHeaderCtx;

typedef struct SigsArray_ {
    SigIntId *sigs;
    uint32_t cnt;
    uint32_t offset; // used to track assign pos
} SigsArray;

typedef struct PrefilterPacketU8HashCtx_ {
    SigsArray *array[256];
} PrefilterPacketU8HashCtx;

#define PREFILTER_U8HASH_MODE_EQ    0
#define PREFILTER_U8HASH_MODE_LT    1
#define PREFILTER_U8HASH_MODE_GT    2
#define PREFILTER_U8HASH_MODE_RA    3

int PrefilterSetupPacketHeader(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx,
            Packet *p, const void *pectx));

int PrefilterSetupPacketHeaderU8Hash(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx,
            Packet *p, const void *pectx));
/* 快速匹配的额外匹配 */
static inline bool
PrefilterPacketHeaderExtraMatch(const PrefilterPacketHeaderCtx *ctx,
                                const Packet *p)
{
    switch (ctx->type)
    {
        case PREFILTER_EXTRA_MATCH_UNUSED:
            break;
        case PREFILTER_EXTRA_MATCH_ALPROTO:
            if (p->flow == NULL || p->flow->alproto != ctx->value)
                return FALSE;
            break;
        case PREFILTER_EXTRA_MATCH_SRCPORT:
            if (p->sp != ctx->value)
                return FALSE;
            break;
        case PREFILTER_EXTRA_MATCH_DSTPORT:
            if (p->dp != ctx->value)
                return FALSE;
            break;
    }
    return TRUE;
}

static inline bool PrefilterIsPrefilterableById(const Signature *s, enum DetectKeywordId kid)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        if (sm->type == kid) {
            return true;
        }
    }
    return false;
}

#endif /* __DETECT_ENGINE_PREFILTER_COMMON_H__ */
