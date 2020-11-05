/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 */

#ifndef __DETECT_FLOWINT_H__
#define __DETECT_FLOWINT_H__

/** Flowint operations allowed */
enum {
    /** Changing integer values */
    FLOWINT_MODIFIER_SET,
    FLOWINT_MODIFIER_ADD,
    FLOWINT_MODIFIER_SUB,

    /** Comparing integer values */
    FLOWINT_MODIFIER_LT,
    FLOWINT_MODIFIER_LE,
    FLOWINT_MODIFIER_EQ,
    FLOWINT_MODIFIER_NE,
    FLOWINT_MODIFIER_GE,
    FLOWINT_MODIFIER_GT,
    /** Checking if a var is set (keyword isset/notset)*/
    FLOWINT_MODIFIER_ISSET,
    FLOWINT_MODIFIER_NOTSET,

    FLOWINT_MODIFIER_UNKNOWN
};

/** The target can be a value, or another variable arleady declared */
enum {
    FLOWINT_TARGET_VAL,
    FLOWINT_TARGET_VAR,
    FLOWINT_TARGET_SELF,
    FLOWINT_TARGET_UNKNOWN
};

/** If the target is another var, get the name and the idx */
typedef struct TargetVar_ {
    char *name;
} TargetVar;

/** Context data for flowint vars */
typedef struct DetectFlowintData_ {
    /* This is the main var we are going to use
    * against the target */
    char *name;           /* 变量名, 如 "http.anomaly.count" */
    /* Internal id of the var */
    uint32_t idx;         /* 变量名在变量空间 g_varnamestore_staging 的序号 */

    /* The modifier/operation/condition we are
    * going to execute */
    uint8_t modifier;     /* FLOWINT_MODIFIER_ADD */
    uint8_t targettype;   /* FLOWINT_TARGET_VAL */

    union {
        /* the target value */
        uint32_t value;   /* 对应FLOWINT_TARGET_VAL的值 */
        /* or the target var */
        TargetVar tvar;      
    } target;
} DetectFlowintData;  /* flowint关键字解析结果, 如”flowint:http.anomaly.count,+,1;“ */

/* prototypes */
void DetectFlowintRegister (void);

#endif /* __DETECT_FLOWINT_H__ */

