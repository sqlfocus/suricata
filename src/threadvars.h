/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#ifndef __THREADVARS_H__
#define __THREADVARS_H__

#include "util-affinity.h"
#include "tm-queues.h"
#include "counters.h"
#include "threads.h"
#include "packet-queue.h"
#include "util-atomic.h"

struct TmSlot_;

/** Thread flags set and read by threads to control the threads */
#define THV_USE                 BIT_U32(0)  /** thread is in use */
#define THV_INIT_DONE           BIT_U32(1)  /** thread initialization done */
#define THV_PAUSE               BIT_U32(2)  /** signal thread to pause itself */
#define THV_PAUSED              BIT_U32(3)  /** the thread is paused atm */
#define THV_KILL                BIT_U32(4)  /** thread has been asked to cleanup and exit */
#define THV_FAILED              BIT_U32(5)  /** thread has encountered an error and failed */
#define THV_CLOSED              BIT_U32(6)  /** thread done, should be joinable */
/* used to indicate the thread is going through de-init.  Introduced as more
 * of a hack for solving stream-timeout-shutdown.  Is set by the main thread. */
#define THV_DEINIT              BIT_U32(7)
#define THV_RUNNING_DONE        BIT_U32(8)  /** thread has completed running and is entering
                                         * the de-init phase */
#define THV_KILL_PKTACQ         BIT_U32(9)  /**< flag thread to stop packet acq */
#define THV_FLOW_LOOP           BIT_U32(10) /**< thread is in flow shutdown loop */

/** signal thread's capture method to create a fake packet to force through
 *  the engine. This is to force timely handling of maintenance taks like
 *  rule reloads even if no packets are read by the capture method. */
#define THV_CAPTURE_INJECT_PKT  BIT_U32(11)
#define THV_DEAD                BIT_U32(12) /**< thread has been joined with pthread_join() */

/** \brief Per thread variable structure */
typedef struct ThreadVars_ {
    pthread_t t;               /* linux线程结构 */
    /** function pointer to the function that runs the packet pipeline for
     *  this thread. It is passed directly to pthread_create(), hence the
     *  void pointers in and out. */ /* "management"->TmThreadsManagement() */
    void *(*tm_func)(void *);  /* 线程主函数, "pktacqloop" -> TmThreadsSlotPktAcqLoop() */

    char name[16];             /* PCAP autofo, 如 RX#01-eth0 */
    char *printable_name;      /* 如 "RX#01-eth0" */
    char *thread_group_name;   /* 如 "Detect" */

    uint8_t thread_setup_flags;

    /** the type of thread as defined in tm-threads.h (TVT_PPT, TVT_MGMT) */
    uint8_t type;

    uint16_t cpu_affinity; /** cpu or core number to set affinity to */
    int thread_priority; /** priority (real time) for this thread. Look at threads.h */


    /** TmModule::flags for each module part of this thread */
    uint8_t tmm_flags;     

    uint8_t cap_flags; /**< Flags to indicate the capabilities of all the
                            TmModules resgitered under this thread */
    uint8_t inq_id;    /* 如 pcap autofp -> TMQH_PACKETPOOL */
    uint8_t outq_id;   /* 如 pcap autofp -> TMQH_FLOW */

    /** local id */
    int id;            /* 在 thread_store->threads[] 中的索引 */

    /** incoming queue and handler */
    Tmq *inq;          /* 非packetpool输入队列; pcap autofp为NULL */
    struct Packet_ * (*tmqh_in)(struct ThreadVars_ *); /* 如 TmqhInputPacketpool() */

    SC_ATOMIC_DECLARE(uint32_t, flags);    /* THV_PAUSE */

    /** list of of TmSlot objects together forming the packet pipeline. */
    struct TmSlot_ *tm_slots;     /* 报文处理函数链, 使用 tmm_modules[] 对象初始化 */

    /** pointer to the flowworker in the pipeline. Used as starting point
     *  for injected packets. Can be NULL if the flowworker is not part
     *  of this thread. */
    struct TmSlot_ *tm_flowworker;/* 指向tm_slots[]中的 TMM_FLOWWORKER 处理函数 */

    /** outgoing queue and handler */
    Tmq *outq;         /* 非 packetpool 输出队列; pcap autofp为NULL */
    void *outctx;      /* 输出环境, TmqhFlowCtx; 输出函数 TmqhOutputFlowHash() */
    void (*tmqh_out)(struct ThreadVars_ *, struct Packet_ *);

    /** queue for decoders to temporarily store extra packets they
     *  generate. */
    PacketQueueNoLock decode_pq;            /* 解码过程中临时产生的报文，如碎片重组后的报文 */

    /** Stream packet queue for flow time out injection. Either a pointer to the
     *  workers input queue or to stream_pq_local */
    struct PacketQueue_ *stream_pq;         /* 首模块"FlowWorker"模块, =->inq->pq, 维护此线程的流报文 */
    struct PacketQueue_ *stream_pq_local;   /* 非模块时, ->stream_pq = ->stream_pq_local(malloc分配) */

    /* counters */

    /** private counter store: counter updates modify this */
    StatsPrivateThreadContext perf_private_ctx;  /* 维护本线程的报文计数统计等，代理了 perf_public_ctx 的链表为数组，提升性能 */

    /** pointer to the next thread */
    struct ThreadVars_ *next;

    /** public counter store: counter syncs update this */
    StatsPublicThreadContext perf_public_ctx;    /* 维护本线程注册的计数量 */

    /* mutex and condition used by management threads */

    SCCtrlMutex *ctrl_mutex;
    SCCtrlCondT *ctrl_cond;

    struct FlowQueue_ *flow_queue;          /* */

} ThreadVars;

/** Thread setup flags: */
#define THREAD_SET_AFFINITY     0x01 /** CPU/Core affinity */
#define THREAD_SET_PRIORITY     0x02 /** Real time priority */
#define THREAD_SET_AFFTYPE      0x04 /** Priority and affinity */

#endif /* __THREADVARS_H__ */
