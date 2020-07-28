/* Copyright (C) 2016 Open Information Security Foundation
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
 * Flow Workers are single thread modules taking care of (almost)
 * everything related to packets with flows:
 *
 * - Lookup/creation
 * - Stream tracking, reassembly
 * - Applayer update
 * - Detection
 *
 * This all while holding the flow lock.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"
#include "detect.h"
#include "stream-tcp.h"
#include "app-layer.h"
#include "detect-engine.h"
#include "output.h"
#include "app-layer-parser.h"

#include "util-validate.h"

#include "flow-util.h"

typedef DetectEngineThreadCtx *DetectEngineThreadCtxPtr;

typedef struct FlowWorkerThreadData_ {
    DecodeThreadVars *dtv;

    union {
        StreamTcpThread *stream_thread;
        void *stream_thread_ptr;
    };

    SC_ATOMIC_DECLARE(DetectEngineThreadCtxPtr, detect_thread);

    void *output_thread; /* Output thread data. */

    uint16_t local_bypass_pkts;  /* 计数器 */
    uint16_t local_bypass_bytes;
    uint16_t both_bypass_pkts;
    uint16_t both_bypass_bytes;

    PacketQueueNoLock pq;        /* 汇聚队列 */

} FlowWorkerThreadData;      /* TMM_FLOWWORKER 环境 */

/** \brief handle flow for packet
 *
 *  Handle flow creation/lookup
 */
static inline TmEcode FlowUpdate(ThreadVars *tv, FlowWorkerThreadData *fw, Packet *p)
{
    FlowHandlePacketUpdate(p->flow, p);   /* 更新流表项 */

    int state = SC_ATOMIC_GET(p->flow->flow_state);
    switch (state) {                      /* 更新bypass统计 */
#ifdef CAPTURE_OFFLOAD
        case FLOW_STATE_CAPTURE_BYPASSED:
            StatsAddUI64(tv, fw->both_bypass_pkts, 1);
            StatsAddUI64(tv, fw->both_bypass_bytes, GET_PKT_LEN(p));
            return TM_ECODE_DONE;
#endif
        case FLOW_STATE_LOCAL_BYPASSED:
            StatsAddUI64(tv, fw->local_bypass_pkts, 1);
            StatsAddUI64(tv, fw->local_bypass_bytes, GET_PKT_LEN(p));
            return TM_ECODE_DONE;
        default:
            return TM_ECODE_OK;
    }
}

static TmEcode FlowWorkerThreadDeinit(ThreadVars *tv, void *data);
/* 初始化 TMM_FLOWWORKER 运行环境 */
static TmEcode FlowWorkerThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    FlowWorkerThreadData *fw = SCCalloc(1, sizeof(*fw));
    if (fw == NULL)
        return TM_ECODE_FAILED;

    SC_ATOMIC_INITPTR(fw->detect_thread);
    SC_ATOMIC_SET(fw->detect_thread, NULL);

    fw->local_bypass_pkts = StatsRegisterCounter("flow_bypassed.local_pkts", tv);
    fw->local_bypass_bytes = StatsRegisterCounter("flow_bypassed.local_bytes", tv);
    fw->both_bypass_pkts = StatsRegisterCounter("flow_bypassed.local_capture_pkts", tv);
    fw->both_bypass_bytes = StatsRegisterCounter("flow_bypassed.local_capture_bytes", tv);

    fw->dtv = DecodeThreadVarsAlloc(tv);
    if (fw->dtv == NULL) {
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }

    /* 构建流汇聚结构，setup TCP */
    if (StreamTcpThreadInit(tv, NULL, &fw->stream_thread_ptr) != TM_ECODE_OK) {
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }
    /* 构建检测环境 */
    if (DetectEngineEnabled()) {
        /* setup DETECT */
        void *detect_thread = NULL;
        if (DetectEngineThreadCtxInit(tv, NULL, &detect_thread) != TM_ECODE_OK) {
            FlowWorkerThreadDeinit(tv, fw);
            return TM_ECODE_FAILED;
        }
        SC_ATOMIC_SET(fw->detect_thread, detect_thread);
    }

    /* 构建输出环境，Setup outputs for this thread. */
    if (OutputLoggerThreadInit(tv, initdata, &fw->output_thread) != TM_ECODE_OK) {
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }

    DecodeRegisterPerfCounters(fw->dtv, tv);
    AppLayerRegisterThreadCounters(tv);

    /* 构建流汇聚队列，setup pq for stream end pkts */
    memset(&fw->pq, 0, sizeof(PacketQueueNoLock));

    *data = fw;
    return TM_ECODE_OK;
}

static TmEcode FlowWorkerThreadDeinit(ThreadVars *tv, void *data)
{
    FlowWorkerThreadData *fw = data;

    DecodeThreadVarsFree(tv, fw->dtv);

    /* free TCP */
    StreamTcpThreadDeinit(tv, (void *)fw->stream_thread);

    /* free DETECT */
    void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);
    if (detect_thread != NULL) {
        DetectEngineThreadCtxDeinit(tv, detect_thread);
        SC_ATOMIC_SET(fw->detect_thread, NULL);
    }

    /* Free output. */
    OutputLoggerThreadDeinit(tv, fw->output_thread);

    /* free pq */
    BUG_ON(fw->pq.len);

    SCFree(fw);
    return TM_ECODE_OK;
}

static void FlowPruneFiles(Packet *p)
{
    if (p->flow && p->flow->alstate) {
        Flow *f = p->flow;
        FileContainer *fc = AppLayerParserGetFiles(f,
                PKT_IS_TOSERVER(p) ? STREAM_TOSERVER : STREAM_TOCLIENT);
        if (fc != NULL) {
            FilePrune(fc);
        }
    }
}
/* 流处理函数入口 */
static TmEcode FlowWorker(ThreadVars *tv, Packet *p, void *data)
{
    FlowWorkerThreadData *fw = data;
    void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);

    SCLogDebug("packet %"PRIu64, p->pcap_cnt);

    /* update time */
    if (!(PKT_IS_PSEUDOPKT(p))) {
        TimeSetByThread(tv->id, &p->ts);
    }

    /* handle Flow */
    if (p->flags & PKT_WANTS_FLOW) {      /* case: 查找/新建流 */
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_FLOW);

        FlowHandlePacket(tv, fw->dtv, p);    /* 查找或建流 */
        if (likely(p->flow != NULL)) {
            DEBUG_ASSERT_FLOW_LOCKED(p->flow);
            if (FlowUpdate(tv, fw, p) == TM_ECODE_DONE) {
                FLOWLOCK_UNLOCK(p->flow);    /* 更新流 */
                return TM_ECODE_OK;
            }
        }
        /* Flow is now LOCKED */

        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_FLOW);

    /* if PKT_WANTS_FLOW is not set, but PKT_HAS_FLOW is, then this is a
     * pseudo packet created by the flow manager. */
    } else if (p->flags & PKT_HAS_FLOW) { /* case: 已经有对应的流，比如已经查找过了 */
        FLOWLOCK_WRLOCK(p->flow);
    }

    SCLogDebug("packet %"PRIu64" has flow? %s", p->pcap_cnt, p->flow ? "yes" : "no");

    /* handle TCP and app layer */
    if (p->flow && PKT_IS_TCP(p)) {       /* TCP协议处理 */
        SCLogDebug("packet %"PRIu64" is TCP. Direction %s", p->pcap_cnt, PKT_IS_TOSERVER(p) ? "TOSERVER" : "TOCLIENT");
        DEBUG_ASSERT_FLOW_LOCKED(p->flow);

        /* if detect is disabled, we need to apply file flags to the flow
         * here on the first packet. */
        if (detect_thread == NULL &&
                ((PKT_IS_TOSERVER(p) && (p->flowflags & FLOW_PKT_TOSERVER_FIRST)) ||
                 (PKT_IS_TOCLIENT(p) && (p->flowflags & FLOW_PKT_TOCLIENT_FIRST))))
        {
            DisableDetectFlowFileFlags(p->flow);
        }

        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_STREAM);
        StreamTcp(tv, p, fw->stream_thread, &fw->pq);  /* 流汇聚 */
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_STREAM);

        if (FlowChangeProto(p->flow)) {
            StreamTcpDetectLogFlush(tv, fw->stream_thread, p->flow, p, &fw->pq);
        }

        /* Packets here can safely access p->flow as it's locked */
        SCLogDebug("packet %"PRIu64": extra packets %u", p->pcap_cnt, fw->pq.len);
        Packet *x;
        while ((x = PacketDequeueNoLock(&fw->pq))) {
            SCLogDebug("packet %"PRIu64" extra packet %p", p->pcap_cnt, x);

            // TODO do we need to call StreamTcp on these pseudo packets or not?
            //StreamTcp(tv, x, fw->stream_thread, &fw->pq, NULL);
            if (detect_thread != NULL) {
                FLOWWORKER_PROFILING_START(x, PROFILE_FLOWWORKER_DETECT);
                Detect(tv, x, detect_thread);          /* 流检测 */
                FLOWWORKER_PROFILING_END(x, PROFILE_FLOWWORKER_DETECT);
            }

            //  Outputs
            OutputLoggerLog(tv, x, fw->output_thread);

            /* put these packets in the preq queue so that they are
             * by the other thread modules before packet 'p'. */
            PacketEnqueueNoLock(&tv->decode_pq, x);
        }

    /* handle the app layer part of the UDP packet payload */
    } else if (p->flow && p->proto == IPPROTO_UDP) {
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_APPLAYERUDP);
        AppLayerHandleUdp(tv, fw->stream_thread->ra_ctx->app_tctx, p, p->flow);
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_APPLAYERUDP);
    }

    PacketUpdateEngineEventCounters(tv, fw->dtv, p);
                                         /* 包解析、流检测事件统计 */
    /* handle Detect */
    DEBUG_ASSERT_FLOW_LOCKED(p->flow);
    SCLogDebug("packet %"PRIu64" calling Detect", p->pcap_cnt);

    if (detect_thread != NULL) {         /* 流检测 */
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_DETECT);
        Detect(tv, p, detect_thread);
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_DETECT);
    }

    // Outputs.                          /* 日志输出 */
    OutputLoggerLog(tv, p, fw->output_thread);

    /* Prune any stored files. */
    FlowPruneFiles(p);                   /* 释放缓存的文件 */

    /*  Release tcp segments. Done here after alerting can use them. */
    if (p->flow != NULL && p->proto == IPPROTO_TCP) {
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_TCPPRUNE);
        StreamTcpPruneSession(p->flow, p->flowflags & FLOW_PKT_TOSERVER ?
                STREAM_TOSERVER : STREAM_TOCLIENT);
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_TCPPRUNE);
    }

    if (p->flow) {                       /* 释放检测环境 */
        DEBUG_ASSERT_FLOW_LOCKED(p->flow);

        /* run tx cleanup last */
        AppLayerParserTransactionsCleanup(p->flow);
        FLOWLOCK_UNLOCK(p->flow);
    }

    return TM_ECODE_OK;
}

void FlowWorkerReplaceDetectCtx(void *flow_worker, void *detect_ctx)
{
    FlowWorkerThreadData *fw = flow_worker;

    SC_ATOMIC_SET(fw->detect_thread, detect_ctx);
}

void *FlowWorkerGetDetectCtxPtr(void *flow_worker)
{
    FlowWorkerThreadData *fw = flow_worker;

    return SC_ATOMIC_GET(fw->detect_thread);
}

const char *ProfileFlowWorkerIdToString(enum ProfileFlowWorkerId fwi)
{
    switch (fwi) {
        case PROFILE_FLOWWORKER_FLOW:
            return "flow";
        case PROFILE_FLOWWORKER_STREAM:
            return "stream";
        case PROFILE_FLOWWORKER_APPLAYERUDP:
            return "app-layer";
        case PROFILE_FLOWWORKER_DETECT:
            return "detect";
        case PROFILE_FLOWWORKER_TCPPRUNE:
            return "tcp-prune";
        case PROFILE_FLOWWORKER_SIZE:
            return "size";
    }
    return "error";
}

static void FlowWorkerExitPrintStats(ThreadVars *tv, void *data)
{
    FlowWorkerThreadData *fw = data;
    OutputLoggerExitPrintStats(tv, fw->output_thread);
}

void TmModuleFlowWorkerRegister (void)
{
    tmm_modules[TMM_FLOWWORKER].name = "FlowWorker";
    tmm_modules[TMM_FLOWWORKER].ThreadInit = FlowWorkerThreadInit;
    tmm_modules[TMM_FLOWWORKER].Func = FlowWorker;
    tmm_modules[TMM_FLOWWORKER].ThreadDeinit = FlowWorkerThreadDeinit;
    tmm_modules[TMM_FLOWWORKER].ThreadExitPrintStats = FlowWorkerExitPrintStats;
    tmm_modules[TMM_FLOWWORKER].cap_flags = 0;
    tmm_modules[TMM_FLOWWORKER].flags = TM_FLAG_STREAM_TM|TM_FLAG_DETECT_TM;
}
