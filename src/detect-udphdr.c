/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-fast-pattern.h"
#include "detect-udphdr.h"

/* prototypes */
static int DetectUdphdrSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectUdphdrRegisterTests (void);
#endif

static int g_udphdr_buffer_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);
/**
 * \brief Registration function for udp.hdr: keyword
 */
void DetectUdphdrRegister(void)
{
    sigmatch_table[DETECT_UDPHDR].name = "udp.hdr";
    sigmatch_table[DETECT_UDPHDR].desc = "sticky buffer to match on the UDP header";
    sigmatch_table[DETECT_UDPHDR].url = "/rules/header-keywords.html#udphdr";
    sigmatch_table[DETECT_UDPHDR].Setup = DetectUdphdrSetup;
    sigmatch_table[DETECT_UDPHDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_UDPHDR].RegisterTests = DetectUdphdrRegisterTests;
#endif

    g_udphdr_buffer_id = DetectBufferTypeRegister("udp.hdr");
    BUG_ON(g_udphdr_buffer_id < 0);             /* 注册检测类型 */

    DetectBufferTypeSupportsPacket("udp.hdr");  /* 支持报文检测 */

    DetectPktMpmRegister("udp.hdr", 2, PrefilterGenericMpmPktRegister, GetData);
                                                       /* 支持多模式匹配(基于报文), 注册到多模式引擎 g_mpm_list[DETECT_BUFFER_MPM_TYPE_PKT]  */
    DetectPktInspectEngineRegister("udp.hdr", GetData, /* 注册到报文检测引擎, g_pkt_inspect_engines */
            DetectEngineInspectPktBufferGeneric);
    return;
}

/**
 * \brief set up the udp.hdr sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectUdphdrSetup (DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_UDP)))
        return -1;

    s->flags |= SIG_FLAG_REQUIRE_PACKET;      /* 基于报文的检测 */

    if (DetectBufferSetActiveList(s, g_udphdr_buffer_id) < 0)
        return -1;                            /* 因为属于sticky buff, 因此激活等待后续修正操作(如to_md5) */

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        if (((uint8_t *)p->udph + (ptrdiff_t)UDP_HEADER_LEN) >
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)))
        {
            SCLogDebug("data out of range: %p > %p",
                    ((uint8_t *)p->udph + (ptrdiff_t)UDP_HEADER_LEN),
                    ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
            return NULL;
        }

        const uint32_t data_len = UDP_HEADER_LEN;
        const uint8_t *data = (const uint8_t *)p->udph;

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-udphdr.c"
#endif
