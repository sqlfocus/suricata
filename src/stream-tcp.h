/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 */

#ifndef __STREAM_TCP_H__
#define __STREAM_TCP_H__

#include "stream-tcp-private.h"

#include "stream.h"
#include "stream-tcp-reassemble.h"

#define STREAM_VERBOSE    FALSE
/* Flag to indicate that the checksum validation for the stream engine
   has been enabled */
#define STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION    BIT_U8(0)  /* 校验和错误后, 此报文不处理 */
#define STREAMTCP_INIT_FLAG_DROP_INVALID           BIT_U8(1)  /* inline模式时, 丢弃非流内报文 */
#define STREAMTCP_INIT_FLAG_BYPASS                 BIT_U8(2)  /* bypass模式, 到达重组深度后, 丢弃报文 */
#define STREAMTCP_INIT_FLAG_INLINE                 BIT_U8(3)  /* inline模式 */

/*global flow data*/
typedef struct TcpStreamCnf_ {
    /** stream tracking
     *
     * max stream mem usage
     *//* 跟踪内存使用状况 */
    SC_ATOMIC_DECLARE(uint64_t, memcap);
    SC_ATOMIC_DECLARE(uint64_t, reassembly_memcap); /**< max memory usage for stream reassembly */

    uint16_t stream_init_flags; /**< new stream flags will be initialized to this */

    /* coccinelle: TcpStreamCnf:flags:STREAMTCP_INIT_ */
    uint8_t flags;
    uint8_t max_synack_queued;

    uint32_t prealloc_sessions; /* 预分配的 TcpSession 数, 描述TCP会话 *< ssns to prealloc per stream thread */
    uint32_t prealloc_segments; /* 预分配的 TcpSegment 数, 描述缓存的段信息 *< segments to prealloc per stream thread */
    int midstream;              /* 中间报文是否可以触发建立 TcpSession */
    int async_oneside;          /* 异步单边，可以理解为单向数据包捕获，即只有一个方向的数据包经过IDS */
    uint32_t reassembly_depth;  /* *< Depth until when we reassemble the stream */

    uint16_t reassembly_toserver_chunk_size;
    uint16_t reassembly_toclient_chunk_size;

    bool streaming_log_api;

    StreamingBufferConfig sbcnf;/* 重组内存的操控方法集 */
} TcpStreamCnf;

typedef struct StreamTcpThread_ {
    int ssn_pool_id;                /* TcpSession, 重组流对象, 对应 ssn_pool->array[] 的索引, */

    /** queue for pseudo packet(s) that were created in the stream
     *  process and need further handling. Currently only used when
     *  receiving (valid) RST packets */
    PacketQueueNoLock pseudo_queue; /* 特殊队列，存储流处理过程中产生的报文，如RST应答等 */

    uint16_t counter_tcp_sessions;
    /** sessions not picked up because memcap was reached */
    uint16_t counter_tcp_ssn_memcap;
    /** pseudo packets processed */
    uint16_t counter_tcp_pseudo;
    /** pseudo packets failed to setup */
    uint16_t counter_tcp_pseudo_failed;
    /** packets rejected because their csum is invalid */
    uint16_t counter_tcp_invalid_checksum;
    /** TCP packets with no associated flow */
    uint16_t counter_tcp_no_flow;
    /** sessions reused */
    uint16_t counter_tcp_reused_ssn;
    /** syn pkts */
    uint16_t counter_tcp_syn;
    /** syn/ack pkts */
    uint16_t counter_tcp_synack;
    /** rst pkts */
    uint16_t counter_tcp_rst;
    /** midstream pickups */
    uint16_t counter_tcp_midstream_pickups;
    /** wrong thread */
    uint16_t counter_tcp_wrong_thread;

    /** tcp reassembly thread data */
    TcpReassemblyThreadCtx *ra_ctx;     /* 流汇聚池 */
} StreamTcpThread;

extern TcpStreamCnf stream_config;
void StreamTcpInitConfig (char);
void StreamTcpFreeConfig(char);
void StreamTcpRegisterTests (void);

void StreamTcpSessionPktFree (Packet *);

void StreamTcpInitMemuse(void);
void StreamTcpIncrMemuse(uint64_t);
void StreamTcpDecrMemuse(uint64_t);
int StreamTcpSetMemcap(uint64_t);
uint64_t StreamTcpGetMemcap(void);
int StreamTcpCheckMemcap(uint64_t);
uint64_t StreamTcpMemuseCounter(void);
uint64_t StreamTcpReassembleMemuseGlobalCounter(void);

Packet *StreamTcpPseudoSetup(Packet *, uint8_t *, uint32_t);

int StreamTcpSegmentForEach(const Packet *p, uint8_t flag,
                        StreamSegmentCallback CallbackFunc,
                        void *data);
void StreamTcpReassembleConfigEnableOverlapCheck(void);
void TcpSessionSetReassemblyDepth(TcpSession *ssn, uint32_t size);

typedef int (*StreamReassembleRawFunc)(void *data, const uint8_t *input, const uint32_t input_len);

int StreamReassembleLog(TcpSession *ssn, TcpStream *stream,
        StreamReassembleRawFunc Callback, void *cb_data,
        uint64_t progress_in,
        uint64_t *progress_out, bool eof);
int StreamReassembleRaw(TcpSession *ssn, const Packet *p,
        StreamReassembleRawFunc Callback, void *cb_data,
        uint64_t *progress_out, bool respect_inspect_depth);
void StreamReassembleRawUpdateProgress(TcpSession *ssn, Packet *p, uint64_t progress);

void StreamTcpDetectLogFlush(ThreadVars *tv, StreamTcpThread *stt, Flow *f, Packet *p, PacketQueueNoLock *pq);

const char *StreamTcpStateAsString(const enum TcpState);
const char *StreamTcpSsnStateAsString(const TcpSession *ssn);

/** ------- Inline functions: ------ */

/**
  * \brief If we are on IPS mode, and got a drop action triggered from
  * the IP only module, or from a reassembled msg and/or from an
  * applayer detection, then drop the rest of the packets of the
  * same stream and avoid inspecting it any further
  * \param p pointer to the Packet to check
  * \retval 1 if we must drop this stream
  * \retval 0 if the stream still legal
  */
static inline int StreamTcpCheckFlowDrops(Packet *p)
{
    /* If we are on IPS mode, and got a drop action triggered from
     * the IP only module, or from a reassembled msg and/or from an
     * applayer detection, then drop the rest of the packets of the
     * same stream and avoid inspecting it any further */
    if (EngineModeIsIPS() && (p->flow->flags & FLOW_ACTION_DROP))
        return 1;

    return 0;
}

enum {
    /* stream has no segments for forced reassembly, nor for detection */
    STREAM_HAS_UNPROCESSED_SEGMENTS_NONE = 0,
    /* stream has no segments for forced reassembly, but only segments that
     * have been sent for detection, but are stuck in the detection queues */
    STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION = 1,
};

TmEcode StreamTcp (ThreadVars *, Packet *, void *, PacketQueueNoLock *);
int StreamNeedsReassembly(const TcpSession *ssn, uint8_t direction);
TmEcode StreamTcpThreadInit(ThreadVars *, void *, void **);
TmEcode StreamTcpThreadDeinit(ThreadVars *tv, void *data);
void StreamTcpRegisterTests (void);

int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt,
                     PacketQueueNoLock *pq);
/* clear ssn and return to pool */
void StreamTcpSessionClear(void *ssnptr);
/* cleanup ssn, but don't free ssn */
void StreamTcpSessionCleanup(TcpSession *ssn);
/* cleanup stream, but don't free the stream */
void StreamTcpStreamCleanup(TcpStream *stream);
/* check if bypass is enabled */
int StreamTcpBypassEnabled(void);
int StreamTcpInlineDropInvalid(void);
int StreamTcpInlineMode(void);

int TcpSessionPacketSsnReuse(const Packet *p, const Flow *f, const void *tcp_ssn);

void StreamTcpUpdateAppLayerProgress(TcpSession *ssn, char direction,
        const uint32_t progress);

#endif /* __STREAM_TCP_H__ */

