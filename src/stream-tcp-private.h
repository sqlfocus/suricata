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
 */

#ifndef __STREAM_TCP_PRIVATE_H__
#define __STREAM_TCP_PRIVATE_H__

#include "tree.h"
#include "decode.h"
#include "util-pool.h"
#include "util-pool-thread.h"
#include "util-streaming-buffer.h"

#define STREAMTCP_QUEUE_FLAG_TS     0x01
#define STREAMTCP_QUEUE_FLAG_WS     0x02
#define STREAMTCP_QUEUE_FLAG_SACK   0x04

/** currently only SYN/ACK */
typedef struct TcpStateQueue_ {
    uint8_t flags;
    uint8_t wscale;
    uint16_t win;
    uint32_t seq;
    uint32_t ack;
    uint32_t ts;
    uint32_t pkt_ts;
    struct TcpStateQueue_ *next;
} TcpStateQueue;

typedef struct StreamTcpSackRecord {
    uint32_t le;    /**< left edge, host order */
    uint32_t re;    /**< right edge, host order */
    RB_ENTRY(StreamTcpSackRecord) rb;
} StreamTcpSackRecord;

int TcpSackCompare(struct StreamTcpSackRecord *a, struct StreamTcpSackRecord *b);

/* red-black tree prototype for SACK records */
RB_HEAD(TCPSACK, StreamTcpSackRecord);
RB_PROTOTYPE(TCPSACK, StreamTcpSackRecord, rb, TcpSackCompare);

typedef struct TcpSegment {
    PoolThreadReserved res;
    uint16_t payload_len;    /* 缓存段长度(当缓存报文一部分时，小于报文长度) */
    uint32_t seq;            /* 缓存段起始序号 */
    RB_ENTRY(TcpSegment) __attribute__((__packed__)) rb;
    StreamingBufferSegment sbseg;  /* 数据在 TcpStream->sb 中的位置: 偏移+长度 */
} __attribute__((__packed__)) TcpSegment;  /* 记录TCP流重组的段信息 */

/** \brief compare function for the Segment tree
 *
 *  Main sort point is the sequence number. When sequence numbers
 *  are equal compare payload_len as well. This way the tree is
 *  sorted by seq, and in case of duplicate seqs we are sorted
 *  small to large.
 */
int TcpSegmentCompare(struct TcpSegment *a, struct TcpSegment *b);

/* red-black tree prototype for TcpSegment */
RB_HEAD(TCPSEG, TcpSegment);
RB_PROTOTYPE(TCPSEG, TcpSegment, rb, TcpSegmentCompare);

#define TCP_SEG_LEN(seg)        (seg)->payload_len
#define TCP_SEG_OFFSET(seg)     (seg)->sbseg.stream_offset

#define SEG_SEQ_RIGHT_EDGE(seg) ((seg)->seq + TCP_SEG_LEN((seg)))

/* get right edge of sequence space of seen segments.
 * Only use if STREAM_HAS_SEEN_DATA is true. */
#define STREAM_SEQ_RIGHT_EDGE(stream)   (stream)->segs_right_edge
#define STREAM_RIGHT_EDGE(stream)       (STREAM_BASE_OFFSET((stream)) + (STREAM_SEQ_RIGHT_EDGE((stream)) - (stream)->base_seq))
/* return true if we have seen data segments. */
#define STREAM_HAS_SEEN_DATA(stream)    (!RB_EMPTY(&(stream)->sb.sbb_tree) || (stream)->sb.stream_offset || (stream)->sb.buf_offset)

typedef struct TcpStream_ {
    uint16_t flags:12;              /* 此方向上到目前收到的所有报文标识 *< Flag specific to the stream e.g. Timestamp */
    /* coccinelle: TcpStream:flags:STREAMTCP_STREAM_FLAG_ */
    uint16_t wscale:4;              /* 发送缓存的窗口扩大因子，[0, 15] */
    uint8_t os_policy;              /* OS_POLICY_BSD, 目的IP对应的主机类型，用于针对性的重组和报文处理 */
    uint8_t tcp_flags;              /* 目前为止看到的标识, TH_SYN */

    uint32_t isn;                   /* tcp起始序号 */
    uint32_t next_seq;              /* 下一个待发送序号 */
    uint32_t last_ack;              /* 已经被ack的序号 */
    uint32_t next_win;              /* 窗口右边缘 */
    uint32_t window;                /* 窗口值 */

    uint32_t last_ts;               /* 上一个报文的时间戳选项值, 用于匹配回显值 */
    uint32_t last_pkt_ts;           /* 上一个报文的时间
                                         This will be used to validate the last_ts, when connection has been idle for
                                         longer time.(RFC 1323)*/
    /* reassembly */
    uint32_t base_seq;              /* 流缓存的起始序号, 一般为syn/synack序号+1,  seq where we are left with reassebly. Matches STREAM_BASE_OFFSET below. */

    uint32_t app_progress_rel;      /* 已处理的缓存计数，相对于 STREAM_BASE_OFFSET */
    uint32_t raw_progress_rel;      /**< raw reassembly progress relative to STREAM_BASE_OFFSET */
    uint32_t log_progress_rel;      /**< streaming logger progress relative to STREAM_BASE_OFFSET */

    uint32_t min_inspect_depth;     /* 应用层设定的最小检测深度，*< min inspect size set by the app layer, to make sure enough data
                                     *   remains available for inspection together with app layer buffers */
    uint32_t data_required;         /* 下次解析，需要提前准备的数据量, *< data required from STREAM_APP_PROGRESS before calling app-layer again */

    StreamingBuffer sb;             /* 缓存的数据 */
    struct TCPSEG seg_tree;         /* 红黑树, 已缓存的数据段的序号和长度, TcpSegment, 数据在->sb中 */
    uint32_t segs_right_edge;       /* 已缓存数据右边界序号 */

    uint32_t sack_size;             /**< combined size of the SACK ranges currently in our tree. Updated
                                     *   at INSERT/REMOVE time. */
    struct TCPSACK sack_tree;       /**< red back tree of TCP SACK records. */
} TcpStream;

#define STREAM_BASE_OFFSET(stream)  ((stream)->sb.stream_offset)
#define STREAM_APP_PROGRESS(stream) (STREAM_BASE_OFFSET((stream)) + (stream)->app_progress_rel)
#define STREAM_RAW_PROGRESS(stream) (STREAM_BASE_OFFSET((stream)) + (stream)->raw_progress_rel)
#define STREAM_LOG_PROGRESS(stream) (STREAM_BASE_OFFSET((stream)) + (stream)->log_progress_rel)

/* from /usr/include/netinet/tcp.h */
enum TcpState
{
    TCP_NONE,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_LAST_ACK,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_CLOSED,
};

/*
 * Per SESSION flags
 */

/** Flag for mid stream session */
#define STREAMTCP_FLAG_MIDSTREAM                    0x0001
/** Flag for mid stream established session */
#define STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED        0x0002
/** Flag for mid session when syn/ack is received */
#define STREAMTCP_FLAG_MIDSTREAM_SYNACK             0x0004
/** Flag for TCP Timestamp option */
#define STREAMTCP_FLAG_TIMESTAMP                    0x0008
/** Server supports wscale (even though it can be 0) */
#define STREAMTCP_FLAG_SERVER_WSCALE                0x0010
/** Closed by RST */
#define STREAMTCP_FLAG_CLOSED_BY_RST                0x0020
/** Flag to indicate that the session is handling asynchronous stream.*/
#define STREAMTCP_FLAG_ASYNC                        0x0040
/** Flag to indicate we're dealing with 4WHS: SYN, SYN, SYN/ACK, ACK
 * (http://www.breakingpointsystems.com/community/blog/tcp-portals-the-three-way-handshake-is-a-lie) */
#define STREAMTCP_FLAG_4WHS                         0x0080
/** Flag to indicate that this session is possible trying to evade the detection
 *  (http://www.packetstan.com/2010/06/recently-ive-been-on-campaign-to-make.html) */
#define STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT    0x0100
/** Flag to indicate the client (SYN pkt) permits SACK */
#define STREAMTCP_FLAG_CLIENT_SACKOK                0x0200
/** Flag to indicate both sides of the session permit SACK (SYN + SYN/ACK) */
#define STREAMTCP_FLAG_SACKOK                       0x0400
// vacancy
/** 3WHS confirmed by server -- if suri sees 3whs ACK but server doesn't (pkt
 *  is lost on the way to server), SYN/ACK is retransmitted. If server sends
 *  normal packet we assume 3whs to be completed. Only used for SYN/ACK resend
 *  event. */
#define STREAMTCP_FLAG_3WHS_CONFIRMED               0x1000
/** App Layer tracking/reassembly is disabled */
#define STREAMTCP_FLAG_APP_LAYER_DISABLED           0x2000
/** Stream can be bypass */
#define STREAMTCP_FLAG_BYPASS                       0x4000
/** SSN uses TCP Fast Open */
#define STREAMTCP_FLAG_TCP_FAST_OPEN                0x8000

/*
 * Per STREAM flags
 */

// bit 0 vacant
/** Flag to avoid stream reassembly/app layer inspection for the stream */
#define STREAMTCP_STREAM_FLAG_NOREASSEMBLY                  BIT_U16(1)
/** we received a keep alive */
#define STREAMTCP_STREAM_FLAG_KEEPALIVE                     BIT_U16(2)
/** Stream has reached it's reassembly depth, all further packets are ignored */
#define STREAMTCP_STREAM_FLAG_DEPTH_REACHED                 BIT_U16(3)
/** Trigger reassembly next time we need 'raw' */
#define STREAMTCP_STREAM_FLAG_TRIGGER_RAW                   BIT_U16(4)
/** Stream supports TIMESTAMP -- used to set ssn STREAMTCP_FLAG_TIMESTAMP
 *  flag. */
#define STREAMTCP_STREAM_FLAG_TIMESTAMP                     BIT_U16(5)
/** Flag to indicate the zero value of timestamp */
#define STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP                BIT_U16(6)
/** App proto detection completed */
#define STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED  BIT_U16(7)
/** App proto detection skipped */
#define STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED    BIT_U16(8)
/** Raw reassembly disabled for new segments */
#define STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED              BIT_U16(9)
/* 被检测引擎用于内容检测, * Raw reassembly disabled completely */
#define STREAMTCP_STREAM_FLAG_DISABLE_RAW                   BIT_U16(10)

#define STREAMTCP_STREAM_FLAG_RST_RECV                      BIT_U16(11)

/** NOTE: flags field is 12 bits */




#define PAWS_24DAYS         2073600         /**< 24 days in seconds */

#define PKT_IS_IN_RIGHT_DIR(ssn, p)        ((ssn)->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK ? \
                                            PKT_IS_TOSERVER(p) ? (p)->flowflags &= ~FLOW_PKT_TOSERVER \
                                            (p)->flowflags |= FLOW_PKT_TOCLIENT : (p)->flowflags &= ~FLOW_PKT_TOCLIENT \
                                            (p)->flowflags |= FLOW_PKT_TOSERVER : 0)

/* Macro's for comparing Sequence numbers
 * Page 810 from TCP/IP Illustrated, Volume 2. */
#define SEQ_EQ(a,b)  ((int32_t)((a) - (b)) == 0)
#define SEQ_LT(a,b)  ((int32_t)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int32_t)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int32_t)((a) - (b)) >= 0)

#define STREAMTCP_SET_RA_BASE_SEQ(stream, seq) { \
    do { \
        (stream)->base_seq = (seq) + 1;    \
    } while(0); \
}

#define StreamTcpSetEvent(p, e) {                                           \
    if ((p)->flags & PKT_STREAM_NO_EVENTS) {                                \
        SCLogDebug("not setting event %d on pkt %p (%"PRIu64"), "     \
                   "stream in known bad condition", (e), p, (p)->pcap_cnt); \
    } else {                                                                \
        SCLogDebug("setting event %d on pkt %p (%"PRIu64")",          \
                    (e), p, (p)->pcap_cnt);                                 \
        ENGINE_SET_EVENT((p), (e));                                         \
    }                                                                       \
}

typedef struct TcpSession_ {
    PoolThreadReserved res;
    uint8_t state:4;                        /* 流状态, TCP_SYN_SENT */
    uint8_t pstate:4;                       /* 旧->state的值, previous state */
    uint8_t queue_len;                      /**< length of queue list below */
    int8_t data_first_seen_dir;             /* 首包方向, STREAM_TOSERVER */
    /** track all the tcp flags we've seen */
    uint8_t tcp_packet_flags;    /* 跟踪此流所有的 Packet->tcph->th_flags, 如 TH_SYN */
    /* coccinelle: TcpSession:flags:STREAMTCP_FLAG */
    uint16_t flags;              /* STREAMTCP_FLAG_ASYNC */
    uint32_t reassembly_depth;   /* 最大缓存深度, 0表示不限制缓存总量, reassembly depth for the stream */
    TcpStream server;            /* 服务器状态信息，跟踪服务器发出的报文 */
    TcpStream client;            /* 客户端状态信息 */
    TcpStateQueue *queue;        /* 存储的syn+ack报文, list of SYN/ACK candidates */
} TcpSession;     /* TCP会话信息，用于跟踪流，流重组等 */

#define StreamTcpSetStreamFlagAppProtoDetectionCompleted(stream) \
    ((stream)->flags |= STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED)
#define StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(stream) \
    ((stream)->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED)
#define StreamTcpResetStreamFlagAppProtoDetectionCompleted(stream) \
    ((stream)->flags &= ~STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED);
#define StreamTcpDisableAppLayerReassembly(ssn) do { \
        SCLogDebug("setting STREAMTCP_FLAG_APP_LAYER_DISABLED on ssn %p", ssn); \
        ((ssn)->flags |= STREAMTCP_FLAG_APP_LAYER_DISABLED); \
    } while (0);

#endif /* __STREAM_TCP_PRIVATE_H__ */
