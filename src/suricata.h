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

/** \mainpage Doxygen documentation
 *
 * \section intro_sec Introduction
 *
 * The Suricata Engine is an Open Source Next Generation Intrusion Detection
 * and Prevention Engine. This engine is not intended to just replace or
 * emulate the existing tools in the industry, but will bring new ideas and
 * technologies to the field.
 *
 * \section dev_doc Developer documentation
 *
 * You've reach the automically generated documentation of Suricata. This
 * document contains information about architecture and code structure. It
 * is attended for developers wanting to understand or contribute to Suricata.
 *
 * \subsection modules Modules
 *
 * Documentation is generate from comments placed in all parts of the code.
 * But you will also find some groups describing specific functional parts:
 *  - \ref decode
 *  - \ref httplayer
 *  - \ref sigstate
 *  - \ref threshold
 *
 * \section archi Architecture
 *
 * \subsection datastruct Data structures
 *
 * Regarding matching, there is three main data structures which are:
 *  - ::Packet: Data relative to an individual packet with information about
 *  linked structure such as the ::Flow the ::Packet belongs to.
 *  - ::Flow: Information about a flow for example a TCP session
 *
 *  \subsection runmode Running mode
 *
 *  Suricata is multithreaded and running modes define how the different
 *  threads are working together. You can see util-runmodes.c for example
 *  of running mode.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __SURICATA_H__
#define __SURICATA_H__

#include "suricata-common.h"
#include "packet-queue.h"

/* the name of our binary */
#define PROG_NAME "Suricata"
#define PROG_VER PACKAGE_VERSION

/* workaround SPlint error (don't know __gnuc_va_list) */
#ifdef S_SPLINT_S
#  include <err.h>
#  define CONFIG_DIR "/etc/suricata"
#endif

#define DEFAULT_CONF_FILE CONFIG_DIR "/suricata.yaml"

#define DEFAULT_PID_DIR LOCAL_STATE_DIR "/run/"
#define DEFAULT_PID_BASENAME "suricata.pid"
#define DEFAULT_PID_FILENAME DEFAULT_PID_DIR DEFAULT_PID_BASENAME

#define DOC_URL "https://suricata.readthedocs.io/en/"
const char *GetDocURL(void);

/* runtime engine control flags */
#define SURICATA_STOP    (1 << 0)   /**< gracefully stop the engine: process all
                                     outstanding packets first */
#define SURICATA_DONE    (1 << 2)   /**< packets capture ended */

/* 引擎的阶段/状态 */
enum {
    SURICATA_INIT = 0,  /* 初始化阶段 */
    SURICATA_RUNTIME,   /* 运行态 */
    SURICATA_DEINIT     /* 退出释放阶段 */
};

/* Engine is acting as */
enum EngineMode {
    ENGINE_MODE_IDS,
    ENGINE_MODE_IPS,
};

void EngineModeSetIPS(void);
void EngineModeSetIDS(void);
int EngineModeIsIPS(void);
int EngineModeIsIDS(void);

/* Box is acting as router */
enum {
    SURI_HOST_IS_SNIFFER_ONLY,   /* for IDS */
    SURI_HOST_IS_ROUTER,         /* for IPS */
};

#define IS_SURI_HOST_MODE_SNIFFER_ONLY(host_mode)  ((host_mode) == SURI_HOST_IS_SNIFFER_ONLY)
#define IS_SURI_HOST_MODE_ROUTER(host_mode)  ((host_mode) == SURI_HOST_IS_ROUTER)

#include "runmodes.h"

typedef struct SCInstance_ {
    enum RunModes run_mode;     /* 运行模式，默认 RUNMODE_PCAP_DEV */
    enum RunModes aux_run_mode; /* 命令行传入的模式, 如 ./suricata --pcap */

    char pcap_dev[128];         /* 监听接口名，通过-i指定 */
    char *sig_file;
    int sig_file_exclusive;
    char *pid_filename;
    char *regex_arg;

    char *keyword_info;
    char *runmode_custom_mode; /* single|autofp|worker, 命令行--runmode指定 */
#ifndef OS_WIN32
    const char *user_name;
    const char *group_name;
    uint8_t do_setuid;
    uint8_t do_setgid;
    uint32_t userid;
    uint32_t groupid;
#endif /* OS_WIN32 */

    bool system;               /* true/false为SYSTEM/USER，USER将使用当前工作目录，如PCAP FILE为USER */
    bool set_logdir;
    bool set_datadir;

    int delayed_detect;        /* 延迟检测标志: 在规则载入前就开始处理数据包，以减少IPS模式下down time */
    int disabled_detect;       /* 是否禁止检测引擎，0/1 */
    int daemon;                /* 是否作为精灵进程运行，由配置参数-D决定 */
    int offline;               /* 是否为离线模式，如PCAP FILE模式 */
    int verbose;               /* 日志详细程度，[0, 4]，对应参数-v/-v -v等（越多次对应INFO级别向更详细方向的次数） */
    int checksum_validation;   /* 是否支持流验证校验和 */

    struct timeval start_time; /* 启动时间 */

    const char *log_dir;
    const char *progname;      /**进程名，指向argv[0] */
    const char *conf_filename; /* 配置文件名，'-c'传入 */
    char *strict_rule_parsing_string;
} SCInstance;


/* memset to zeros, and mutex init! */
void GlobalsInitPreConfig(void);

extern volatile uint8_t suricata_ctl_flags;
extern int g_disable_randomness;
extern uint16_t g_vlan_mask;

#include <ctype.h>
#define u8_tolower(c) tolower((uint8_t)(c))
#define u8_toupper(c) toupper((uint8_t)(c))

void EngineStop(void);
void EngineDone(void);

int RunmodeIsUnittests(void);
int RunmodeGetCurrent(void);
int IsRuleReloadSet(int quiet);

int SuriHasSigFile(void);

extern int run_mode;

int SuricataMain(int argc, char **argv);
int InitGlobal(void);
int PostConfLoadedSetup(SCInstance *suri);
void PostConfLoadedDetectSetup(SCInstance *suri);

void PreRunInit(const int runmode);
void PreRunPostPrivsDropInit(const int runmode);
void PostRunDeinit(const int runmode, struct timeval *start_time);
void RegisterAllModules(void);

const char *GetProgramVersion(void);

#endif /* __SURICATA_H__ */

