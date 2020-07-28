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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __DETECT_APP_LAYER_EVENT_H__
#define __DETECT_APP_LAYER_EVENT_H__

typedef struct DetectAppLayerEventData_ {
    AppProto alproto;  /* ALPROTO_DNS, 事件"app-layer-event:dns.malformed_data;"中的dns对应的索引 */
    int event_id;      /* 事件"app-layer-event:applayer_unexpected_protocol;"中值对应的索引, 参考表 app_layer_event_pkt_table[] */
                       /* 事件"app-layer-event:dns.malformed_data;"中协议的事件表的索引，参考表 http_decoder_event_table */
    /* it's used to check if there are event set into the detect engine */
    bool needs_detctx; /* 事件"app-layer-event:file.xxx"中协议为file时 = true */

    char *arg;         /* 事件"app-layer-event:dns.malformed_data;"的值复制 */
} DetectAppLayerEventData;

int DetectAppLayerEventPrepare(DetectEngineCtx *de_ctx, Signature *s);
void DetectAppLayerEventRegister(void);

#endif /* __DETECT_APP_LAYER_EVENT_H__ */
