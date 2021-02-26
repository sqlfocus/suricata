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
 * \ingroup sigstate
 *
 * @{
 */

/**
 * \file
 *
 * \brief Data structures and function prototypes for keeping
 *        state for the detection engine.
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */


#ifndef __DETECT_ENGINE_STATE_H__
#define __DETECT_ENGINE_STATE_H__

#define DETECT_ENGINE_INSPECT_SIG_NO_MATCH 0
#define DETECT_ENGINE_INSPECT_SIG_MATCH 1
#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH 2
/** indicate that the file inspection portion of a sig didn't match.
 *  This is used to handle state keeping as the detect engine is still
 *  only marginally aware of files. */
#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES 3
/** hack to work around a file inspection limitation. Since there can be
 *  multiple files in a TX and the detection engine really don't know
 *  about that, we have to give the file inspection engine a way to
 *  indicate that one of the files matched, but that there are still
 *  more files that have ongoing inspection. */
#define DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_FILES 4

/** number of DeStateStoreItem's in one DeStateStore object */
#define DE_STATE_CHUNK_SIZE             15

/* per sig flags */
#define DE_STATE_FLAG_FULL_INSPECT              BIT_U32(0)
#define DE_STATE_FLAG_SIG_CANT_MATCH            BIT_U32(1)
/* flag set if file inspecting sig did not match, but might need to be
 * re-evaluated for a new file in a tx */
#define DE_STATE_ID_FILE_INSPECT                2UL  /* 动态注册类型files, 有状态检测的引擎序号 */
#define DE_STATE_FLAG_FILE_INSPECT              BIT_U32(DE_STATE_ID_FILE_INSPECT)

/* first bit position after the built-ins */
#define DE_STATE_FLAG_BASE                      3UL  /* 动态注册类型, 有状态检测的普通起始序号 */

/* state flags
 *
 * Used by app-layer-parsers to notify us that new files
 * are available in the tx.
 *//* 告知检测引擎, 有新文件 */
#define DETECT_ENGINE_STATE_FLAG_FILE_NEW       BIT_U8(0)

typedef struct DeStateStoreItem_ {
    uint32_t flags;
    SigIntId sid;    /* 命中的 Signature 索引 */
} DeStateStoreItem;

typedef struct DeStateStore_ {
    DeStateStoreItem store[DE_STATE_CHUNK_SIZE];
    struct DeStateStore_ *next;
} DeStateStore;

typedef struct DetectEngineStateDirection_ {
    DeStateStore *head;
    DeStateStore *tail;
    SigIntId cnt;           /* 已匹配规则计数, head/tail链表长度 */
    uint16_t filestore_cnt; /* */
    uint8_t flags;          /* DETECT_ENGINE_STATE_FLAG_FILE_NEW */
    /* coccinelle: DetectEngineStateDirection:flags:DETECT_ENGINE_STATE_FLAG_ */
} DetectEngineStateDirection;  /* 某方向上, 事务检测引擎状态 */

typedef struct DetectEngineState_ {
    DetectEngineStateDirection dir_state[2];
} DetectEngineState;           /* 事务检测引擎状态 */

// TODO
typedef struct DetectTransaction_ {
    void *tx_ptr;          /* 事务数据结构, htp_tx_t */
    const uint64_t tx_id;  /* 事务索引 */
    struct AppLayerTxData *tx_data_ptr;   /* 事务标识, 定义在 rust/src/applayer.rs */
    DetectEngineStateDirection *de_state; /* 事务检测引擎状态 */
    const uint64_t detect_flags;          /* detect flags get/set from/to applayer */
    uint64_t prefilter_flags;             /* 匹配的 PrefilterEngine->local_id 的或; prefilter flags for direction, to be updated by prefilter code */
    const uint64_t prefilter_flags_orig;  /* prefilter flags for direction, before prefilter has run */
    const int tx_progress; /* 当前状态, 取值enum同->tx_end_state */
    const int tx_end_state;/* 事务结束状态码, HTP_RESPONSE_COMPLETE */
} DetectTransaction; /* 事务检测时的状态信息 */

/**
 * \brief Alloc a DetectEngineState object.
 *
 * \retval Alloc'd instance of DetectEngineState.
 */
DetectEngineState *DetectEngineStateAlloc(void);

/**
 * \brief Frees a DetectEngineState object.
 *
 * \param state DetectEngineState instance to free.
 */
void DetectEngineStateFree(DetectEngineState *state);

/**
 *  \brief Update the inspect id.
 *
 *  \param f unlocked flow
 *  \param flags direction and disruption flags
 */
void DeStateUpdateInspectTransactionId(Flow *f, const uint8_t flags,
        const bool tag_txs_as_inspected);

void DetectEngineStateResetTxs(Flow *f);

void DeStateRegisterTests(void);


void DetectRunStoreStateTx(
        const SigGroupHead *sgh,
        Flow *f, void *tx, uint64_t tx_id,
        const Signature *s,
        uint32_t inspect_flags, uint8_t flow_flags,
        const uint16_t file_no_match);

void DetectRunStoreStateTxFileOnly(
        const SigGroupHead *sgh,
        Flow *f, void *tx, uint64_t tx_id,
        const uint8_t flow_flags,
        const uint16_t file_no_match);

#endif /* __DETECT_ENGINE_STATE_H__ */

/**
 * @}
 */
