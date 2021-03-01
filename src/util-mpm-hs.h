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

/**
 * \file
 *
 * \author Jim Xu <jim.xu@windriver.com>
 * \author Justin Viiret <justin.viiret@intel.com>
 *
 * MPM pattern matcher that calls the Hyperscan regex matcher.
 */

#ifndef __UTIL_MPM_HS__H__
#define __UTIL_MPM_HS__H__

typedef struct SCHSPattern_ {
    /* length of the pattern */
    uint16_t len;
    /* flags describing the pattern */
    uint8_t flags;
    /* holds the original pattern that was added */
    uint8_t *original_pat;      /* 添加时的pattern */
    /* pattern id */
    uint32_t id;                /* id/offset/depth作为区分的要素 */

    uint16_t offset;
    uint16_t depth;

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;             /* 对应的sid列表, AppLayerProtoDetectPMSignature */

    /* only used at ctx init time, when this structure is part of a hash
     * table. */
    struct SCHSPattern_ *next;
} SCHSPattern;

typedef struct SCHSCtx_ {
    /* hash used during ctx initialization */
    SCHSPattern **init_hash;    /* 规则hash表，编译后内存释放 */

    /* pattern database and pattern arrays. */
    void *pattern_db;           /* hyperscan编译结果, PatternDatabase */

    /* size of database, for accounting. */
    size_t hs_db_size;          /* 编译结果大小 */
} SCHSCtx;

typedef struct SCHSThreadCtx_ {
    /* Hyperscan scratch space region for this thread, capable of handling any
     * database that has been compiled. */
    void *scratch;        /* MPM_HS -> hs_scratch_t */

    /* size of scratch space, for accounting. */
    size_t scratch_size;
} SCHSThreadCtx;

void MpmHSRegister(void);

void MpmHSGlobalCleanup(void);

#endif /* __UTIL_MPM_HS__H__ */
