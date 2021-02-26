#+BEGIN_EXAMPLE
安装 ~https://github.com/OISF/libhtp~

sudo apt-get install libtool pkg-config libpcre3-dev libyaml-dev libjansson-dev
sudo apt-get install libpcap-dev
sudo apt-get install rustc cargo

sh ./autogen.sh
./configure --enable-non-bundled-htp
make
make install
make install-conf

suricata --pcap
#+END_EXAMPLE

本文档介绍suricata主流程，以便于快速浏览
  1. 可参考单元测试 RunUnittests() 入口，了解环境初始化，以便于支持lib编译
  2. TODO 协议解析/ TCP状态机/ 流重组/ 日志输出/ 存储

--SuricataMain()
  --InitGlobal()
    --RunModeRegisterRunModes()    注册运行模式, runmodes[RUNMODE_PCAP_DEV]
  --ParseCommandLine()
    --ParseCommandLinePcapLive()   解析命令行-i，赋值运行模式 RUNMODE_PCAP_DEV
  --LoadYamlConfig()
  --SCLogLoadConfig()              初始化调试输出
    --SCLogInitLogModule()
  --PostConfLoadedSetup()
    --MpmTableSetup()              注册多模匹配算法, mpm_table[MPM_HS]
      --MpmHSRegister()
    --SpmTableSetup()              注册单模匹配算法, spm_table[SPM_HS]
      --SpmHSRegister()
    --AppLayerSetup()              初始化应用层协议解析环境
      --AppLayerParserRegisterProtocolParsers()
      --AppLayerProtoDetectPrepareState()
    --SCHInfoLoadFromConfig()      加载主机os信息等，以更好的适配检测策略
    --SigTableSetup()              注册检测规则关键字, sigmatch_table[]
    --TmqhSetup()                  注册典型队列，用于线程间通信, tmqh_table[TMQH_SIMPLE]
    --PacketAlertTagInit()         初始化 g_tag_signature/g_tag_pa
    --RegisterAllModules()         注册、初始化线程模块, tmm_modules[]
      --TmModuleReceivePcapRegister()
      --TmModuleDecodePcapRegister()    pcap收包/解析 TMM_RECEIVEPCAP/TMM_DECODEPCAP
      --TmModuleLoggerRegister()          注册输出模块
    --TmModuleRunInit()
    --InitSignalHandler()          注册信号处理函数
    --PreRunInit()
      --DefragInit()               IP重组初始化
      --IPPairInitConfig()
      --FlowInitConfig()           流模块初始化
      --StreamTcpInitConfig()      TCP流重组初始化
  --PreRunPostPrivsDropInit()
    --RunModeInitializeOutputs()   激活输出模块
  --PostConfLoadedDetectSetup()
    --DetectEngineCtxInit()        初始化检测引擎, DetectEngineCtx
    --LoadSignatures()             加载检测规则文件
  --RunModeDispatch()
    --RunModeGetCustomMode()       选择运行模型, runmodes[RUNMODE_PCAP_DEV]
    --RunMode->RunModeFunc()       运行模式初始化, RunModeIdsPcapWorkers()
    --FlowManagerThreadSpawn()
    --FlowRecyclerThreadSpawn()    启动流管理/回收线程
    --StatsSpawnThreads()          启动统计线程
  --UnixManagerThreadSpawnNonRunmode()
    --UnixManagerInit()            启动命令行, TMM_UNIXMANAGER/UnixManager()
  --SuricataMainLoop()
    --DetectEngineReload()         主循环，处理SIGUSR2信号，重新加载规则引擎

* 重要的全局变量
SCInstance suricata        全局环境数据
RunModes runmodes[]        引擎支持的运行模式
Tmqh tmqh_table[]          支持的队列类型
TmModule tmm_modules[]     支持的报文处理模块

    
* 调试输出初始化
SCLogConfig *sc_log_config         日志配置信息结构
    
--SuricataMain()
  --InitGlobal()               解析配置文件前，初始化日志输出为CONSOLE
    --SCLogInitLogModule()
  --SCLogLoadConfig()          解析配置文件后，重新初始化调试输出模块
    --ConfGetNode()                读取"logging.outputs"配置
    --SCLogInitLogModule()
    

* 应用层协议解析 - HTTP
    
--AppLayerSetup()                  应用协议解析环境初始化
  --AppLayerProtoDetectSetup()     初始化 alpd_ctx/AppLayerProtoDetectCtx
  --AppLayerParserSetup()          初始化 alp_ctx/AppLayerParserCtx
  --AppLayerParserRegisterProtocolParsers()
    --RegisterHTPParsers()         注册HTTP识别关键字/解析函数
      --HTPRegisterPatternsForProtocolDetection()
        --AppLayerProtoDetectPMRegisterPatternCI()  注册请求/应答关键字(如GET)，单模引擎
          --AppLayerProtoDetectPMRegisterPattern()  更新 alpd_ctx->ctx_ipp[].ctx_pm[].head
      --AppLayerParserRegisterParser()              报文解析操作, 更新 alp_ctx.ctxs[]
      --HTPConfigure()             注册libhtp回调; 分析http配置信息, 存储到 cfgtree/cfglist
      --AppLayerProtoDetectPPParseConfPorts()
        --AppLayerProtoDetectPPRegister()           注册知名端口号(SSL为例), alpd_ctx->ctx_pp[]
  --AppLayerProtoDetectPrepareState()               
    --AppLayerProtoDetectPMSetContentIDs()
    --AppLayerProtoDetectPMMapSignatures()          将上述注册的单模规则，编译构建为多模引擎
    --AppLayerProtoDetectPMPrepareMpm()             alpd_ctx.ctx_ipp[].ctx_pm[].mpm_ctx


--AppLayerHandleTCPData()     应用识别入口
  --TCPProtoDetect()
    --AppLayerProtoDetectGetProto()     协议识别
      --AppLayerProtoDetectPMGetProto()     基于规则
      --AppLayerProtoDetectPPGetProto()     基于端口
      --AppLayerProtoDetectPEGetProto()     基于特殊配置
  --AppLayerParserParse()               协议解析
    --AppLayerParserProtoCtx->Parser()
      ==HTPHandleRequestData()              http请求解析
      ==HTPHandleResponseData()             http应答解析

--HTPConfigSetDefaultsPhase1()各阶段回调
  --HTPCallbackRequestStart()
  --HTPCallbackRequestHeaderData()      收到请求头
  --HTPCallbackRequestBodyData()        收到请求体
    --HtpRequestBodyHandleMultipart()
    --HtpRequestBodyHandlePOSTorPUT()
      --HTPFileOpen()                       缓存文件
      --HTPFileStoreChunk()
      --HTPFileClose()
  --HTPCallbackRequest()                请求结束
  --HTPCallbackResponseStart()          应答开始
  --HTPCallbackResponseHeaderData()     收到应答头
  --HTPCallbackResponseBodyData()
    --HtpResponseBodyHandle()
      --HTPFileOpen()                       缓存文件
  --HTPCallbackResponse()

--OutputFilestoreLogger()     日志阶段, 输出缓存文件

                                                       
* 应用层协议解析 - SSL/TLS
--AppLayerParserRegisterProtocolParsers()
  --RegisterSSLParsers()      注册SSL识别关键字, 解析函数
                                                       

                                                       
* 基于规则的安全检测
配置文件目录: /path/to/suricata/etc/
规则文件目录: /path/to/suricata/rules/
日志输出控制: /path/to/suricata/threshold.config

                                                       
--SuricataMain()
  --PostConfLoadedSetup()
    --SigTableSetup()              注册检测规则关键字及处理函数, 如sid/rev, SigTableElmt
      --DetectSidRegister()                       sigmatch_table[DETECT_SID]
      --DetectHttpUriRegister()
        --DetectAppLayerInspectEngineRegister2()  应用检测引擎, 加入 g_app_inspect_engines
        --DetectAppLayerMpmRegister2()            多模检测引擎, g_mpm_list[DETECT_BUFFER_MPM_TYPE_APP]
          --SupportFastPatternForSigMatchList()   加入快速匹配链表 sm_fp_support_smlist_list
        --DetectBufferTypeGetByName()             注册检测类型, 加入 g_buffer_type_hash
      --DetectAppLayerEventRegister()             注册应用层检测/识别产生的事件的处理句柄
  --PostConfLoadedDetectSetup()
    --DetectEngineCtxInit()        初始化检测引擎, DetectEngineCtx
      --DetectEngineCtxLoadConf()                 加载配置文件, "detect:"配置
      --DetectBufferTypeSetupDetectEngine()       记录已注册的检测类型、检测引擎等
      --SRepInit()                                加载IP信誉库
        --SRepLoadCatFile()
        --SRepLoadFile()
      --SCClassConfLoadClassficationConfigFile()  解析 classification.config
      --SCRConfLoadReferenceConfigFile()          解析 reference.config
      --ActionInitConfig()                        初始化动作优先级, action_order_sigs[]
      --VarNameStoreSetupStaging()                初始化变量名空间, g_varnamestore_staging
    --LoadSignatures()
      --SigLoadSignatures()
        1--ProcessSigFiles()       加载检测规则文件, suricata.rules等
          --DetectLoadSigFile()
            --DetectEngineAppendSig()             解析检测规则, Signature
              --SigInit()
                --SigInitHelper()
                  --SigParse()
                    --SigParseBasics()
                    --SigParseOptions()           调用 sigmatch_table[].Setup()
                    --DetectIPProtoRemoveAllSMs() 去除 DETECT_IPPROTO 类型的SigMatch
                  --DetectAppLayerEventPrepare()
                    --DetectAppLayerEventSetupP2()"app-layer-events"阶段2
                  --SigBuildAddressMatchArray()   规则源/目的IP列表变更为数组，以加速匹配
                  --DetectBufferRunSetupCallback()进一步构建检测类型环境, 如根据urilen设定限制内容检测长度/转换为小写
                    --DetectBufferType->SetupCallback()
                  --SigValidate()                 合法性检测, 并调整标识
                  --SignatureSetType()
                  --IPOnlySigParseAddress()       构建IPonly加速查找数据结构
        1--SCSigRegisterSignatureOrderingFuncs()  注册规则优先级函数
        --SCSigOrderSignatures()                  按优先级排序规则列表
        --SCThresholdConfInitContext()            解析threshold.config文件: 限制“嘈杂”规则的日志输出速率
        --SigGroupBuild()          调整规则列表为运行时刻需要的结构
          2--DetectSetFastPatternAndItsId()
            --RetrieveFPForSig()   提取可作为fast pattern的匹配, 为后续prefilter构建提供基础
          --SigInitStandardMpmFactoryContexts()
          --SigAddressPrepareStage1()
            --SignatureCreateMask()               初始化规则标志位, 如 SIG_MASK_REQUIRE_PAYLOAD 等
            --RuleSetWhitelist()
            --DetectBufferRunSetupCallback()
              --DetectBufferType->SetupCallback()
            --DetectFlowbitsAnalyze()
          --SigAddressPrepareStage2()
            --RulesGroupByPorts()                 构建基于端口的规则组
            --RulesGroupByProto()                 非TCP/UDP协议的规则组
            --IPOnlyPrepare()                     构建IPonly检测规则组
          --SigAddressPrepareStage3()
            --DetectEngineBuildDecoderEventSgh()  构建基于事件的规则组/SIG_FLAG_INIT_DEONLY
          2--SigAddressPrepareStage4()
            --SigGroupHeadSetFilestoreCount()     获取规则组的标识, 以加速匹配
            --PrefilterSetupRuleGroup()           构建规则组的prefilter多模环境
              --PatternMatchPrepareGroup()
                --MpmStorePrepareBuffer()
                  --MpmStoreSetup()
                    --PopulateMpmHelperAddPattern()
                    --mpm_table[].Prepare()
                --PrepareAppMpms()
                  --DetectBufferMpmRegistery->PrefilterRegisterWithListId()
                  ==>PrefilterGenericMpmRegister()    加入SigGroupHead->init->tx_engines
                --PreparePktMpms()
                  --DetectBufferMpmRegistery->PrefilterRegisterWithListId()
              --sigmatch_table[].SetupPrefilter()     构建配置prefilter关键字的prefilter检测引擎, 加入SigGroupHead->init->pkt_engines
            --SigGroupHeadBuildNonPrefilterArray()汇总规则组的非prefilter的规则
          2--DetectMpmPrepareBuiltinMpms()
          --DetectMpmPrepareAppMpms()             共享环境构建多模引擎
          --DetectMpmPreparePktMpms()
          --SigMatchPrepare()                     初始化单规则的检测引擎 Signature->app_inspect/pkt_inspect
            --DetectEngineAppInspectionEngine2Signature()
            --DetectEnginePktInspectionSetup()
              --DetectEngineInspectRulePayloadMatches()
              --DetectEngineInspectRulePacketMatches()
          --VarNameStoreActivateStaging()         激活变量命名空间

                                                       
--TmThreadsSlotPktAcqLoop()
  --TmSlot->SlotThreadInit()    初始化PIPELINE处理函数环境
    --FlowWorkerThreadInit()    初始化 TMM_FLOWWORKER 运行环境
      --DetectEngineThreadCtxInit()     检测环境
        --ThreadCtxDoInit()
          --PatternMatchThreadPrepare() 初始化多模匹配环境
          --PmqSetup()                  prefilter引擎匹配结果存储地
          --SpmMakeThreadCtx()          初始化单模匹配环境

                                                       
--FlowWorker()
  --Detect()                    DetectEngineThreadCtx
    --DetectFlow()              基于流的检测
      --DetectRun()
    --DetectNoFlow()            无流检测
      --DetectRun()
        1--DetectRunSetup()           构建检测环境, 检查是否有待检测重组原始数据
          --StreamReassembleRawHasDataReady()
        --DetectRunInspectIPOnly()   IPonly规则引擎, DetectEngineIPOnlyCtx->tree_ipv4src
          --IPOnlyMatchPacket()
            --搜索DetectEngineCtx->io_ctx->tree_ipv4src/tree_ipv4dst
            --IP/端口匹配/
            --匹配 Signature->sm_arrays[DETECT_SM_LIST_MATCH]
            --匹配 Signature->sm_arrays[DETECT_SM_LIST_POSTMATCH]
        1--DetectRunGetRuleGroup()    获取基于端口的规则组
          --SigMatchSignaturesGetSgh()
        --DetectRunPrefilterPkt()    运行prefilters引擎
          --Prefilter()
            --匹配 SigGroupHead->pkt_engines
            --匹配 SigGroupHead->payload_engines
          --合并匹配结果 + 非prefilter规则, 作为后续逐条匹配的规则集
        1--DetectRulePacketRules()    prefilter结果规则, 运行逐报文规则
          --DetectEnginePktInspectionRun()
            --匹配 Signature->pkt_engines
            --运行 Signature->sm_arrays[DETECT_SM_LIST_POSTMATCH]
        --DetectRunTx()              上一步结果, 运行事务/应用检测
          --DetectRunPrefilterTx()
            --匹配 SigGroupHead->tx_engines
          --加入前置已匹配规则 DetectEngineThreadCtx->match_array[]
          --加入保留规则 htp_tx_t->user_data->de_state->dir_state[]->head
          --DetectRunTxInspectRule()
            --匹配 Signature->app_inspect
          --匹配后 Signature->sm_arrays[DETECT_SM_LIST_POSTMATCH]
        1--DetectRunPostRules()       检测后处理, 匹配Threshold规则，去掉部分告警
          --PacketAlertFinalize()
            --PacketAlertHandle()
            --TagHandlePacket()
            --FlowSetHasAlertsFlag()

    
    
* 运行模式初始化，RunMode->RunModeFunc()
解析 RUNMODE_PCAP_DEV 模式的"workers"/run-to-death运行方式
根据底层网卡数创建线程，每个网卡的线程数和接收通道数匹配，线程名"W#01-eth0"

--RunModeIdsPcapWorkers()
  --RunModeSetLiveCaptureWorkers()
    --RunModeSetLiveCaptureWorkersForDevice()
      --TmThreadCreatePacketHandler()
        --TmThreadCreate()         初始化线程环境 ThreadVars
          --TmqGetQueueByName()/TmqCreateQueue()  获取/创建队列, tmq_list[]
            --输入->inq  --- "packetpool"
            --输出->outq --- "packetpool"
          --TmqhGetQueueHandlerByName()           获取队列处理函数, tmqh_table[]
            --输入->tmqh_in --- "packetpool" -> TMQH_PACKETPOOL
            --输出->tmqh_out--- "packetpool" -> TMQH_PACKETPOOL
          --TmThreadSetSlots()     设置主处理函数
            --"pktacqloop" --- ->tm_func = TmThreadsSlotPktAcqLoop()
        --TmThreadsRegisterThread()注册到 thread_store
      --TmSlotSetFuncAppend()      添加4个处理函数, ThreadVars->tm_slots
        --"ReceivePcap"   -> TMM_RECEIVEPCAP
        --"DecodePcap"    -> TMM_DECODEPCAP
        --"FlowWorker"    -> TMM_FLOWWORKER
        --"RespondReject" -> TMM_RESPONDREJECT
      --TmThreadSpawn()            创建线程
    
对于autofp模式的pcap，采用pipeline形式; 由于报文在前置线程分配, 并且由
尾端线程释放, 两者采用锁+信号量同步, 可能存在性能问题
接口监听线程, RX#01-eth0
    收包, 名"packetpool", 处理"packetpool"
       ThreadVars->inq_id/tmqh_in = TMQH_PACKETPOOL/TmqhInputPacketpool()
       ThreadVars->inq = NULL
    发包, 名"pickup0", 处理"flow"
       ThreadVars->outq_id/tmqh_out = TMQH_FLOW/TmqhOutputFlowHash()
       ThreadVars->outq = "pickup0"
    ->tm_func: "pktacqloop"/TmThreadsSlotPktAcqLoop()
    ->tm_slots: "ReceivePcap" - "DecodePcap"
    
流处理线程, W#01-eth0
    收包, 名"pickup0", 处理"flow"
       ThreadVars->inq = "pickup0"
       ThreadVars->inq_id/tmqh_in = TMQH_FLOW/TmqhInputFlow()
    发包, 名"packetpool", 处理"packetpool"
       ThreadVars->outq_id/tmqh_out = TMQH_PACKETPOOL/TmqhOutputPacketpool()
       ThreadVars->outq = NULL
    ->tm_func: "varslot"/TmThreadsSlotVar()
    ->tm_slots: "FlowWorker" - "RespondReject"

* RUNMODE_PCAP_DEV运行模式
分析此模式下"workers"工作方式的运行代码

--TmThreadsSlotPktAcqLoop()
  --PacketPoolInit()               初始化报文池
  --TmSlot->SlotThreadInit()       初始化PIPELINE处理函数环境
    --ReceivePcapThreadInit()
    --DecodePcapThreadIni()
    --FlowWorkerThreadInit()       初始化 TMM_FLOWWORKER 运行环境
      --DecodeThreadVarsAlloc()       协议识别环境
      --StreamTcpThreadInit()         流汇聚环境
      --DetectEngineThreadCtxInit()   检测环境
        --ThreadCtxDoInit()
      --OutputLoggerThreadInit()      输出环境
  --while(True)
    --ReceivePcapLoop()            主循环, ThreadVars->tm_slots[0]->PktAcqLoop
      --pcap_dispatch()
        --PcapCallbackLoop()
          --PacketCopyData()          读取报文
          --TmThreadsSlotProcessPkt() 运行函数处理链
            --DecodePcap()
            --FlowWorker()
            --RespondRejectFunc()
          --PcapDumpCounters()        底层抓包统计，如接口丢包等

    
* L1-L4解码
从底层PCAP接收报文后，通过此函数处理L1-L4解码; 对于GRE等tunnel报文;
其每发现一层, 就新创建一个报文, 重走解码流程及后续检测流程, 以保证
内、外层报文头均过检测, 但仅有内层过内容检测。中间构建的tunnel报文
除最外层报文(root)由最内层报文释放时一块释放外, 其他报文走正常的释
放逻辑
        
--DecodePcap()
  --DecodeLinkLayer()
    --DecodeEthernet()
      --DecodeNetworkLayer()
        --DecodeIPV4()
          --DecodeIPV4Packet()
            --DecodeIPV4Options()  解析IP选项
          --Defrag()               报文重组
          --DecodeTCP()
            --DecodeTCPPacket()
              --DecodeTCPOptions() 解析TCP选项
            --FlowSetupPacket()
              --FlowGetHash()      计算hash值，设置 PKT_WANTS_FLOW 标识
    
    
* tmm_modules[TMM_FLOWWORKER]->Func, 流处理入口
流表hash数组是共享的，因此具有锁保护
                              
--FlowWorker()
  --FlowHandlePacket()             查找流表
  --FlowUpdate()
  --------TCP处理-------
  --StreamTcp()                    流汇聚
  --Detect()                       流检测
  --------UDP处理-------
  --AppLayerHandleUdp()
    --AppLayerProtoDetectGetProto()协议识别
    --AppLayerParserParse()        应用层解析
  ----------------------
  --PacketUpdateEngineEventCounters()包解析、流检测事件统计
  --Detect()
  --OutputLoggerLog()
  --FlowPruneFiles()               释放缓存的文件
  --StreamTcpPruneSession()        释放流重组
  --AppLayerParserTransactionsCleanup()   释放检测环境

    
* 流
线程主函数"management" <==> ThreadVars->tm_func = TmThreadsManagement()
处理链"FlowManager" <==> tmm_modules[TMM_FLOWMANAGER]->Management = FlowManager()
FlowConfig flow_config;            流全局配置信息

--SuricataMain()
  --PostConfLoadedSetup()
    --PreRunInit()
      --FlowInitConfig()           初始化流资源, 配置流超时等参数
  --RunModeDispatch()
    --FlowManagerThreadSpawn()
      --TmThreadCreateMgmtThreadByName()
        --TmThreadCreate()         确定入口函数, TmThreadsManagement()
        --TmSlotSetFuncAppend()    确定槽函数, FlowManager()
    --FlowRecyclerThreadSpawn()    执行函数 TmThreadsManagement()/FlowRecycler()

                                       
--DecodePcap()
  --DecodeLinkLayer()
    --DecodeEthernet()
      --DecodeNetworkLayer()
        --DecodeIPV4()
          --DecodeTCP()
            --FlowSetupPacket()    打标 PKT_WANTS_FLOW
              --FlowGetHash()      计算hash值, 为建流/查询流准备
    
--FlowWorker()                     线程中流全程加锁??? 不加锁的表, 流程中可能被强制征用
  --FlowHandlePacket()
    --FlowGetFlowFromHash()        新建/查找流, 设置 PKT_HAS_FLOW
  --FlowUpdate()
    --FlowHandlePacketUpdate()
  --FlowWorkerProcessInjectedFlows() 处理被管理线程注入的超时的流
  --FlowWorkerProcessLocalFlows()    处理本线程的移除的超时的流

                                       
--TmThreadsManagement()
  --FlowManagerThreadInit()
  --FlowManager()                  管理流/老化流入口
    --FlowUpdateSpareFlows()         0号线程，平衡全局池流表量, 维持在预分配的90%~110%
    --FlowTimeoutHash()
      --ProcessAsideQueue()          流老化, 回收到 flow_recycle_q 队列
    --DefragTimeoutHash()            0号线程，老化其他hash表
    --HostTimeoutHash()
    --IPPairTimeoutHash()
                                       
  --FlowRecyclerThreadInit()
  --FlowRecycler()                 调用注册的流日志输出模块, OutputFlowLogger
    --Recycler()
      --OutputFlowLog()              日志
      --FlowClearMemory()            清理内存
        --FLOW_RECYCLE()
          --FlowCleanupAppLayer()    清理应用解析
      --FlowSparePoolReturnFlow()    回收流对象


* TCP流重组/应用协议识别
tcp协议上的应用层协议检测时，需要做数据重组
    
--SuricataMain()
  --PostConfLoadedSetup()
    --PreRunInit()
      --StreamTcpInitConfig()      读取TCP流重组配置文件
        --StreamTcpReassembleInit()
        --FlowSetProtoFreeFunc()     注册 flow_freefuncs[], StreamTcpSessionClear()

    
--TmThreadsSlotPktAcqLoop()        PCAP入口函数
  --TmSlot->SlotThreadInit()
  -->FlowWorkerThreadInit()        初始化 TMM_FLOWWORKER 运行环境
    --StreamTcpThreadInit()        初始化流汇聚环境, FlowWorkerThreadData->stream_thread_ptr/StreamTcpThread

    
--FlowWorker()
  --StreamTcp()                    流汇聚入口
    --StreamTcpPacket()
      --StreamTcpPacketStateNone()    无会话时进入，如syn报文
        --StreamTcpNewSession()           新建会话, TcpSession, Packet->flow->protoctx
      --StreamTcpStateDispatch()      有会话时进入，维护tcp状态机
        --StreamTcpPacketStateSynSent()      处理syn+ack报文
        --StreamTcpPacketStateSynRecv()      处理ack报文
          --StreamTcpReassembleHandleSegment()   基于报文的流汇聚
        --StreamTcpPacketStateEstablished()  正常交互报文


--StreamTcpReassembleHandleSegment()
  --StreamTcpReassembleHandleSegmentUpdateACK()
    --StreamTcpReassembleAppLayer()              对端已缓存数据处理
      --ReassembleUpdateAppLayer()
        --AppLayerHandleTCPData()
          --TCPProtoDetect()
            --AppLayerProtoDetectGetProto()         协议识别
              --AppLayerProtoDetectPMGetProto()        基于规则
              --AppLayerProtoDetectPPGetProto()        基于端口
              --AppLayerProtoDetectPEGetProto()        基于特殊配置
            --AppLayerParserParse()                 协议解析
          --AppLayerParserParse()
  --StreamTcpReassembleHandleSegmentHandleData() 缓存数据, TcpStream
    --StreamTcpReassembleInsertSegment()
      --DoInsertSegment()
      --InsertSegmentDataCustom()


* 事件日志输出模块
--SuricataMain()
  --RegisterAllModules()
    --TmModuleLoggerRegister()       注册输出方式和模块
      --OutputRegisterRootLoggers()    底层输出方式, registered_loggers
      --OutputRegisterLoggers()        上层应用的输出模块, output_modules
    --TmModuleStatsLoggerRegister()    统计输出, tmm_modules[TMM_STATSLOGGER]
  --PreRunPostPrivsDropInit()    
    --RunModeInitializeOutputs()     激活日志模块
      --OutputModule->InitFunc()       fast -> AlertFastLogInitCtx()
      --AddOutputToFreeList()          加入 output_free_list
      --SetupOutput()                  按类型加入列表，如packet/tx/file/streaming logger, 初始化 logger_bits[]
      --AppLayerParserRegisterLoggerBits()   更新 alp_ctx.ctxs[][].logger_bits
      --OutputSetupActiveLoggers()
        --RootLogger->ActiveCntFunc()  加入 active_loggers


--TmThreadsSlotPktAcqLoop()          PCAP入口函数，线程级别初始化
  --TmSlot->SlotThreadInit()
  -->FlowWorkerThreadInit()          初始化 TMM_FLOWWORKER 运行环境
    --RootLogger->ThreadInit()       日志输出初始化, 报文输出方式 = OutputLoggerThreadInit()
    
    
--FlowWorker()
  --OutputLoggerLog()
    --RootLogger->LogFunc()          遍历 active_loggers, 输出日志
    ==OutputPacketLog()
    ==OutputTxLog()
    ==OutputFiledataLog()
    ==OutputFileLog()
    ==OutputStreamingLog()


* 统计计数
suricata支持丰富的计数种类，包括协议类型计数、异常解析计数等

--SuricataMain()
  --PostConfLoadedSetup()
    --RegisterAllModules()
      --TmModuleLoggerRegister()
        --OutputRegisterLoggers()
          --LogStatsLogRegister()       对应"stats"
          --JsonStatsLogRegister()      注册 统计输出方式, JsonStatsLogger(), 对应"stats-json"/"eve-log.stats"
      --TmModuleStatsLoggerRegister()   注册 TMM_STATSLOGGER 统计输出模块
    --PreRunInit()
      --StatsInit()                     统计环境初始化
  --PreRunPostPrivsDropInit()
    --StatsSetupPostConfigPreOutput()   解析统计输出配置
    --RunModeInitializeOutputs()
    --StatsSetupPostConfigPostOutput()  记录启动时间, 并检测是否能够输出统计
  --RunModeDispatch()
    --StatsSpawnThreads()               启动统计输出线程
      --TmThreadCreateMgmtThread()        线程1: 设定统计量输出标志, StatsWakeupThread()
                                          线程2: 输出统计量到文件, StatsMgmtThread()


--TmThreadsSlotPktAcqLoop()     PCAP线程入口
  --PacketPoolInit()
  --TmSlot->SlotThreadInit()         PIPELINE函数初始化
  ==ReceivePcapThreadInit()          注册底层收包统计量, PcapThreadVars->capture_kernel_packets
    --StatsRegisterCounter()
  ==DecodePcapThreadInit()
    --DecodeRegisterPerfCounters()   注册统计计数量的ID, DecodeThreadVars->counter_pkts
      --StatsRegisterCounter()       注册到 ThreadVars->perf_public_ctx->head[]
        --StatsRegisterQualifiedCounter()
      --StatsRegisterAvgCounter()
      --StatsRegisterMaxCounter()
  ==FlowWorkerThreadInit()
    --StreamTcpThreadInit()          注册到流汇聚统计量, FlowWorkerThreadData->stream_thread_ptr
      --StatsRegisterCounter()
    --DetectEngineThreadCtxInit()
      --StatsRegisterCounter()       注册Detect统计量, FlowWorkerThreadData->detect_thread->counter_alerts
    --AppLayerRegisterThreadCounters() 注册支持的应用协议计数量, applayer_counters[]
  --StatsSetupPrivate()              将线程统计量加入到全局列表
    --StatsGetAllCountersArray()
      --StatsGetCounterArrayRange()     初始化 ThreadVars->perf_private_ctx
    --StatsThreadRegister()             加入 stats_ctx
--TmThreadsManagement()         流管理线程入口
  --FlowManagerThreadInit()
    --StatsRegisterCounter()         注册流管理统计量, FlowManagerThreadData->flow_mgr_cnt_clo


    
--DecodePcap()                  统计
  --DecodeUpdatePacketCounters()     报文bps/pps计数
  --DecodeLinkLayer()
    --DecodeEthernet()
      --StatsIncr()                  二层头计数
      --DecodeNetworkLayer()
        --DecodeIPV4()
          --StatsIncr()              三层计数
          --DecodeTCP()
            --StatsIncr()            四层计数
  --PacketDecodeFinalize()
    --StatsIncr()                    异常报文计数



--StatsWakeupThread()           线程, 设定统计量标志, 每隔3s一次
  --遍历 tv_root[TVT_PPT]
    --设置 ThreadVars->perf_public_ctx.perf_flag
    --SCCondSignal(ThreadVars->inq->pq->cond_q)
  --遍历 tv_root[TVT_MGMT]
    --设置 ThreadVars->perf_public_ctx.perf_flag


--ReceivePcapLoop()             PCAP报文处理
  --StatsSyncCountersIfSignalled()/StatsSyncCounters()
    --StatsUpdateCounterArray()    将私有部分同步到公有部分，冷热同步
      --StatsCopyCounterValue()
      --清理 ThreadVars->perf_public_ctx.perf_flag
    
    
--StatsMgmtThread()             线程, 输出统计量到文件
  --TmModule->ThreadInit()         初始化 TMM_STATSLOGGER, 初始化日志方式列表 stats_thread_data
  ==OutputStatsLogThreadInit()
  --StatsOutput()
    --OutputStatsLog()             通过注册的日志方式输出
      --遍历线程数据，归并
      --数据新旧切换
      --OutputStatsLogger->LogFunc()
      ==JsonStatsLogger()


* 文件存储
‘filestore’关键字可用于定制需要存储的文件; 配置文件'output.file-store'用于
管理文件存储行为

--SuricataMain()
  --PostConfLoadedSetup()
    --SigTableSetup()
      --DetectFilemagicRegister()       filemagic关键字
      --DetectFilestoreRegister()       filestore关键字
    --RegisterAllModules()
      --TmModuleLoggerRegister()
        --OutputRegisterRootLoggers()
          --OutputFiledataLoggerRegister() 注册文件输出方式, 添加到 registered_loggers
        --OutputRegisterLoggers()
          --OutputFilestoreRegister()      注册文件存储模块, 添加到 output_modules
  --PreRunPostPrivsDropInit()
    --RunModeInitializeOutputs()
      --OutputModule->InitFunc()
      -->OutputFilestoreLogInitCtx()     output.file-store配置解析
      --SetupOutput()
        --OutputRegisterFiledataLogger() 注册模块到输出方式对应的列表, list/output_filedata.c

--TmThreadsSlotPktAcqLoop()
  --TmSlot->SlotThreadInit()
  -->FlowWorkerThreadInit()
    --OutputLoggerThreadInit()
      --RootLogger->ThreadInit()
      -->OutputFilestoreLogThreadInit() 初始化文件存储模块
                                               
--AppLayerHandleTCPData()               应用识别入口
  --AppLayerParserParse()
    --AppLayerParserProtoCtx->Parser()
      ==HTPHandleRequestData()            http请求解析
      ==HTPHandleResponseData()           http应答解析

--HTPConfigSetDefaultsPhase1()          各阶段回调
  --HTPCallbackRequestStart()
  --HTPCallbackRequestHeaderData()        收到请求头
  --HTPCallbackRequestBodyData()          收到请求体
    --HtpRequestBodyHandleMultipart()
    --HtpRequestBodyHandlePOSTorPUT()
      --HTPFileOpen()                     缓存文件
      --HTPFileStoreChunk()
      --HTPFileClose()
  --HTPCallbackRequest()                  请求结束
  --HTPCallbackResponseStart()            应答开始
  --HTPCallbackResponseHeaderData()       收到应答头
  --HTPCallbackResponseBodyData()
    --HtpResponseBodyHandle()
      --HTPFileOpen()
        --FileFlowToFlags()               根据流标识->file_flags更新缓存文件File->flags
  --HTPCallbackResponse()

--FlowWorker()
  --Detect()
    --DetectFlow()
      --DetectRun()
        --DetectRunGetRuleGroup()
          --DetectRunPostGetFirstRuleGroup()
            --DetectPostInspectFileFlagsUpdate()
              --FileUpdateFlowFileFlags() 更新流标识->file_flags
  --OutputLoggerLog()
    --RootLogger->LogFunc()
    -->OutputFiledataLog()
      --OutputFiledataLogFfc()
        --CallLoggers()
          --OutputFiledataLogger->LogFunc()
          -->OutputFilestoreLogger()      日志阶段, 输出缓存文件
  --FlowPruneFiles()
    --FilePrune()                         清理文件/内存
      --FilePruneFile()
      --FileFree()
                                       
* 单元测试
单元测试是整个suricata稳定性的重要一环
编译时需引入 ~UNITTESTS~ 宏定义, 可通过 ~./configure --enable-unittests~ 引入
#+BEGIN_EXAMPLE
./suricata --list-unittests   #列举所有单元测试用例函数名
./suricata -u                 #运行所有单元测试
./suricata -U "ddos*" -u      #仅运行以“ddos”起始的用例函数
#+END_EXAMPLE
    
--SuricataMain()
  --InitGlobal()
    --RunModeRegisterRunModes()
      --UtRunModeRegister()     注册 RUNMODE_UNITTEST
  --ParseCommandLine()          解析命令行
  --StartInternalRunMode()
    --RunUnittests()            运行单元测试
