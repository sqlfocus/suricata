/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Gerardo Iglesias  <iglesiasg@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-urilen.h"

#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"

#include "app-layer-htp.h"
#include "detect-http-uri.h"
#include "detect-uricontent.h"
#include "stream-tcp.h"

#ifdef UNITTESTS
static void DetectHttpUriRegisterTests(void);
#endif
static void DetectHttpUriSetupCallback(const DetectEngineCtx *de_ctx,
                                       Signature *s);
static bool DetectHttpUriValidateCallback(const Signature *s, const char **sigerror);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static int DetectHttpUriSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
static int DetectHttpRawUriSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectHttpRawUriSetupCallback(const DetectEngineCtx *de_ctx,
                                          Signature *s);
static bool DetectHttpRawUriValidateCallback(const Signature *s, const char **);
static InspectionBuffer *GetRawData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static int DetectHttpRawUriSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);

static int g_http_raw_uri_buffer_id = 0; /* "http_raw_uri"对应的检测类型ID */
static int g_http_uri_buffer_id = 0;     /* "http_uri"对应的检测类型ID/DetectBufferType->id */

/**
 * \brief Registration function for keywords: http_uri and http.uri
 */
void DetectHttpUriRegister (void)
{
    /* HTTP URI的规范化后的缓存, http_uri content modifier */
    sigmatch_table[DETECT_AL_HTTP_URI].name = "http_uri";
    sigmatch_table[DETECT_AL_HTTP_URI].desc = "content modifier to match specifically and only on the HTTP uri-buffer";
    sigmatch_table[DETECT_AL_HTTP_URI].url = "/rules/http-keywords.html#http-uri-and-http-raw-uri";
    sigmatch_table[DETECT_AL_HTTP_URI].Setup = DetectHttpUriSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_URI].RegisterTests = DetectHttpUriRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_URI].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_URI].alternative = DETECT_HTTP_URI;

    /* http.uri sticky buffer */
    sigmatch_table[DETECT_HTTP_URI].name = "http.uri";
    sigmatch_table[DETECT_HTTP_URI].alias = "http.uri.normalized";
    sigmatch_table[DETECT_HTTP_URI].desc = "sticky buffer to match specifically and only on the normalized HTTP URI buffer";
    sigmatch_table[DETECT_HTTP_URI].url = "/rules/http-keywords.html#http-uri-and-http-raw-uri";
    sigmatch_table[DETECT_HTTP_URI].Setup = DetectHttpUriSetupSticky;
    sigmatch_table[DETECT_HTTP_URI].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_uri", ALPROTO_HTTP,  /* 注册到应用检测引擎, g_app_inspect_engines */
            SIG_FLAG_TOSERVER, HTP_REQUEST_LINE,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("http_uri", SIG_FLAG_TOSERVER, 2,    /* 注册到多模检测引擎, g_mpm_list[DETECT_BUFFER_MPM_TYPE_APP] */
            PrefilterGenericMpmRegister, GetData, ALPROTO_HTTP,
            HTP_REQUEST_LINE);

    DetectBufferTypeSetDescriptionByName("http_uri",      /* 添加描述性语句 */
            "http request uri");

    DetectBufferTypeRegisterSetupCallback("http_uri",     /* 添加构建回调函数, 一条规则解析完毕(调用setup()后), 调用此函数 */
            DetectHttpUriSetupCallback);

    DetectBufferTypeRegisterValidateCallback("http_uri",  /* 添加验证回调函数, 一条规则解析完毕后由 SigValidate() 调用 */
            DetectHttpUriValidateCallback);
                                                          /* 存储检测类型 */
    g_http_uri_buffer_id = DetectBufferTypeGetByName("http_uri");

    /* HTTP URI的原始缓存; http_raw_uri content modifier */
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].name = "http_raw_uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].desc = "content modifier to match on the raw HTTP uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].url = "/rules/http-keywords.html#http_uri-and-http_raw-uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].Setup = DetectHttpRawUriSetup;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].alternative = DETECT_HTTP_URI_RAW;

    /* http.uri.raw sticky buffer */
    sigmatch_table[DETECT_HTTP_URI_RAW].name = "http.uri.raw";
    sigmatch_table[DETECT_HTTP_URI_RAW].desc = "sticky buffer to match specifically and only on the raw HTTP URI buffer";
    sigmatch_table[DETECT_HTTP_URI_RAW].url = "/rules/http-keywords.html#http-uri-and-http-raw-uri";
    sigmatch_table[DETECT_HTTP_URI_RAW].Setup = DetectHttpRawUriSetupSticky;
    sigmatch_table[DETECT_HTTP_URI_RAW].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_raw_uri", ALPROTO_HTTP,
            SIG_FLAG_TOSERVER, HTP_REQUEST_LINE,
            DetectEngineInspectBufferGeneric, GetRawData);

    DetectAppLayerMpmRegister2("http_raw_uri", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetRawData, ALPROTO_HTTP,
            HTP_REQUEST_LINE);

    DetectBufferTypeSetDescriptionByName("http_raw_uri",
            "raw http uri");

    DetectBufferTypeRegisterSetupCallback("http_raw_uri",
            DetectHttpRawUriSetupCallback);

    DetectBufferTypeRegisterValidateCallback("http_raw_uri",
            DetectHttpRawUriValidateCallback);

    g_http_raw_uri_buffer_id = DetectBufferTypeGetByName("http_raw_uri");
}

/**
 * \brief this function setups the http_uri modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
/* 构建"http_uri"关键字 */
int DetectHttpUriSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectEngineContentModifierBufferSetup(de_ctx, s, str,
                                                  DETECT_AL_HTTP_URI,
                                                  g_http_uri_buffer_id,
                                                  ALPROTO_HTTP);
}

static bool DetectHttpUriValidateCallback(const Signature *s, const char **sigerror)
{
    return DetectUrilenValidateContent(s, g_http_uri_buffer_id, sigerror);
}

static void DetectHttpUriSetupCallback(const DetectEngineCtx *de_ctx,
                                       Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    DetectUrilenApplyToContent(s, g_http_uri_buffer_id);
}

/**
 * \brief this function setup the http.uri keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 *//* 设定sticky buffer, 指向g_http_uri_buffer_id, 被此关键字修饰 */
static int DetectHttpUriSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_uri_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}
/* "http_uri"关键字对应的应用检测引擎, 获取检测buffer的回调函数: DetectEngineAppInspectionEngine->v2.GetData() */
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) { /* 如果尚无检测buffer, 则构建 */
        htp_tx_t *tx = (htp_tx_t *)txv;
        HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);

        if (tx_ud == NULL || tx_ud->request_uri_normalized == NULL) {
            SCLogDebug("no tx_id or uri");
            return NULL;           /* 获取libhtp规范化的uri内存 */
        }

        const uint32_t data_len = bstr_len(tx_ud->request_uri_normalized);
        const uint8_t *data = bstr_ptr(tx_ud->request_uri_normalized);

        InspectionBufferSetup(buffer, data, data_len);        /* 构建原始内存 */
        InspectionBufferApplyTransforms(buffer, transforms);  /* 转变处理, 如去除空格等 */
    }

    return buffer;
}

/**
 * \brief Sets up the http_raw_uri modifier keyword.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Signature to which the current keyword belongs.
 * \param arg    Should hold an empty string always.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int DetectHttpRawUriSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(de_ctx, s, arg,
                                                  DETECT_AL_HTTP_RAW_URI,
                                                  g_http_raw_uri_buffer_id,
                                                  ALPROTO_HTTP);
}

static bool DetectHttpRawUriValidateCallback(const Signature *s, const char **sigerror)
{
    return DetectUrilenValidateContent(s, g_http_raw_uri_buffer_id, sigerror);
}

static void DetectHttpRawUriSetupCallback(const DetectEngineCtx *de_ctx,
                                          Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    DetectUrilenApplyToContent(s, g_http_raw_uri_buffer_id);
}

/**
 * \brief this function setup the http.uri.raw keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpRawUriSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_raw_uri_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

static InspectionBuffer *GetRawData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;
        if (unlikely(tx->request_uri == NULL)) {
            return NULL;
        }
        const uint32_t data_len = bstr_len(tx->request_uri);
        const uint8_t *data = bstr_ptr(tx->request_uri);

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS /* UNITTESTS */
#include "tests/detect-http-uri.c"
#endif /* UNITTESTS */

/**
 * @}
 */
