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
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 *
 */

#include "suricata-common.h"
#include "queue.h"
#include "suricata.h"
#include "conf.h"
#include "util-debug.h"
#include "util-misc.h"
#include "defrag-config.h"

static SCRadixTree *defrag_tree = NULL;   /* 特定IP范围的重组超时 */

static int default_timeout = 0;           /* 默认碎片重组超时 */

static void DefragPolicyFreeUserData(void *data)
{
    if (data != NULL)
        SCFree(data);

    return;
}
/* 特定IP范围（掩码形式的元素），设置其重组超时 */
static void DefragPolicyAddHostInfo(char *host_ip_range, uint64_t timeout)
{
    uint64_t *user_data = NULL;

    if ( (user_data = SCMalloc(sizeof(uint64_t))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Error allocating memory. Exiting");
        exit(EXIT_FAILURE);
    }

    *user_data = timeout;        /* radix用户数据为重组超时 */

    if (strchr(host_ip_range, ':') != NULL) {
        SCLogDebug("adding ipv6 host %s", host_ip_range);
        if (SCRadixAddKeyIPV6String(host_ip_range, defrag_tree, (void *)user_data) == NULL) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                        "failed to add ipv6 host %s", host_ip_range);
        }
    } else {                     /* "192.168.1.0/24"加入defrag_tree */
        SCLogDebug("adding ipv4 host %s", host_ip_range);
        if (SCRadixAddKeyIPV4String(host_ip_range, defrag_tree, (void *)user_data) == NULL) {
            SCLogWarning(SC_ERR_INVALID_VALUE,
                        "failed to add ipv4 host %s", host_ip_range);
        }
    }
}

static int DefragPolicyGetIPv4HostTimeout(uint8_t *ipv4_addr)
{
    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4BestMatch(ipv4_addr, defrag_tree, &user_data);
    if (user_data == NULL)
        return -1;

    return *((int *)user_data);
}

static int DefragPolicyGetIPv6HostTimeout(uint8_t *ipv6_addr)
{
    void *user_data = NULL;
    (void)SCRadixFindKeyIPV6BestMatch(ipv6_addr, defrag_tree, &user_data);
    if (user_data == NULL)
        return -1;

    return *((int *)user_data);
}

int DefragPolicyGetHostTimeout(Packet *p)
{
    int timeout = 0;

    if (PKT_IS_IPV4(p))
        timeout = DefragPolicyGetIPv4HostTimeout((uint8_t *)GET_IPV4_DST_ADDR_PTR(p));
    else if (PKT_IS_IPV6(p))
        timeout = DefragPolicyGetIPv6HostTimeout((uint8_t *)GET_IPV6_DST_ADDR(p));

    if (timeout <= 0)
        timeout = default_timeout;

    return timeout;
}
/* 解析defrag.host-config的下一级节点的配置信息 */
static void DefragParseParameters(ConfNode *n)
{
    ConfNode *si;
    uint64_t timeout = 0;
    /* 定制特定IP的特定超时 */
    TAILQ_FOREACH(si, &n->head, next) {
        if (strcasecmp("timeout", si->name) == 0) {  /* 超时 */
            SCLogDebug("timeout value  %s", si->val);
            if (ParseSizeStringU64(si->val, &timeout) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing timeout "
                        "from conf file");
            }
        }
        if (strcasecmp("address", si->name) == 0) {  /* 地址 */
            ConfNode *pval;
            TAILQ_FOREACH(pval, &si->head, next) {
                DefragPolicyAddHostInfo(pval->val, timeout);
            }
        }
    }
}

void DefragSetDefaultTimeout(intmax_t timeout)
{
    default_timeout = timeout;
    SCLogDebug("default timeout %d", default_timeout);
}
/* 从配置文件读取特定IP段的碎片重组超时 */
void DefragPolicyLoadFromConfig(void)
{
    SCEnter();
    /* 创建radix树 */
    defrag_tree = SCRadixCreateRadixTree(DefragPolicyFreeUserData, NULL);
    if (defrag_tree == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Can't alloc memory for the defrag config tree.");
        exit(EXIT_FAILURE);
    }
    /* 读取 defrag.host-config 配置 */
    ConfNode *server_config = ConfGetNode("defrag.host-config");
    if (server_config == NULL) {
        SCLogDebug("failed to read host config");
        SCReturn;
    }

    SCLogDebug("configuring host config %p", server_config);
    ConfNode *sc;
    /* 读取配置文件，初始化 defrag_tree */
    TAILQ_FOREACH(sc, &server_config->head, next) {
        ConfNode *p = NULL;

        TAILQ_FOREACH(p, &sc->head, next) {
            SCLogDebug("parsing configuration for %s", p->name);
            DefragParseParameters(p);
        }
    }
}

void DefragTreeDestroy(void)
{
    if (defrag_tree != NULL) {
        SCRadixReleaseRadixTree(defrag_tree);
    }
    defrag_tree = NULL;
}
