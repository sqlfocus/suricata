本文档介绍suricata主流程，以便于快速浏览
  1. 可参考单元测试 RunUnittests() 入口，了解环境初始化，以便于支持lib编译
  2. TODO 协议解析/ TCP状态机/ 流重组/ 日志输出/ 存储

--SuricataMain()
  --InitGlobal()
    --RunModeRegisterRunModes()    注册运行模式, runmodes[RUNMODE_PCAP_DEV]
  --ParseCommandLine()
    --ParseCommandLinePcapLive()   解析命令行-i，赋值运行模式 RUNMODE_PCAP_DEV
  --LoadYamlConfig()
  --SCLogLoadConfig()              初始化日志输出
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
  --SuricataMainLoop()
    --DetectEngineReload()         主循环，处理SIGUSR2信号，重新加载规则引擎

* 重要的全局变量
SCInstance suricata        全局环境数据
RunModes runmodes[]        引擎支持的运行模式

    
* 日志环境初始化
SCLogConfig *sc_log_config         日志配置信息结构
    
--SuricataMain()
  --InitGlobal()               解析配置文件前，初始化日志输出为CONSOLE
    --SCLogInitLogModule()
  --SCLogLoadConfig()          解析配置文件后，重新初始化日志
    --ConfGetNode()                读取"logging.outputs"配置
    --SCLogInitLogModule()
    

* 应用层协议解析环境初始化 AppLayerSetup()
本函数构建应用层协议解析环境
    
--AppLayerSetup()
  --AppLayerProtoDetectSetup()     初始化 alpd_ctx/AppLayerProtoDetectCtx
  --AppLayerParserSetup()          初始化 alp_ctx/AppLayerParserCtx
  --AppLayerParserRegisterProtocolParsers()
    --RegisterHTPParsers()
      --HTPRegisterPatternsForProtocolDetection()
        --AppLayerProtoDetectPMRegisterPatternCI()  注册GET等关键字，单模引擎
          --AppLayerProtoDetectPMRegisterPattern()  更新 alpd_ctx->ctx_ipp[].ctx_pm[].head
      --AppLayerParserRegisterParser()              报文解析操作, 更新 alp_ctx.ctxs[]
      --HTPConfigure()             分析http配置信息, 存储到 cfgtree/cfglist构建多模匹配引擎
      --AppLayerProtoDetectPPParseConfPorts()
        --AppLayerProtoDetectPPRegister()           注册知名端口号(SSL为例), alpd_ctx->ctx_pp[]
  --AppLayerProtoDetectPrepareState()               
    --AppLayerProtoDetectPMSetContentIDs()
    --AppLayerProtoDetectPMMapSignatures()          将上述注册的单模规则，编译构建为多模引擎
    --AppLayerProtoDetectPMPrepareMpm()             alpd_ctx.ctx_ipp[].ctx_pm[].mpm_ctx


* 检测环境初始化
单独摘录检测环境初始化流程，以更清晰展现
    
--SuricataMain()
  --PostConfLoadedSetup()
    --SigTableSetup()              注册检测规则关键字及处理函数
      --DetectSidRegister()                       sigmatch_table[DETECT_SID]
      --DetectHttpUriRegister()
        --DetectAppLayerInspectEngineRegister2()  应用检测引擎, 加入 g_app_inspect_engines
        --DetectAppLayerMpmRegister2()            多模检测引擎, g_mpm_list[DETECT_BUFFER_MPM_TYPE_APP]
          --SupportFastPatternForSigMatchList()   加入快速匹配链表 sm_fp_support_smlist_list
        --DetectBufferTypeGetByName()             注册检测类型, 加入 g_buffer_type_hash
      --DetectAppLayerEventRegister()             注册应用层检测/识别产生的事件的处理句柄
  --PostConfLoadedDetectSetup()
    --DetectEngineCtxInit()        初始化检测引擎, DetectEngineCtx
      --DetectEngineCtxLoadConf()                 加载配置文件
      --SRepInit()                                加载IP信誉库
        --SRepLoadCatFile()
        --SRepLoadFile()
      --SCClassConfLoadClassficationConfigFile()  解析 classification.config
      --SCRConfLoadReferenceConfigFile()          解析 reference.config
      --ActionInitConfig()                        初始化动作优先级, action_order_sigs[]
      --VarNameStoreSetupStaging()                初始化变量名空间, g_varnamestore_staging
    --LoadSignatures()
      --SigLoadSignatures()
        --ProcessSigFiles()        加载检测规则文件, suricata.rules等
          --DetectLoadSigFile()
            --DetectEngineAppendSig()             解析检测规则, Signature
              --SigInit()
                --SigInitHelper()
                  --SigParse()
                    --SigParseBasics()
                    --SigParseOptions()           调用 sigmatch_table[].Setup()
                  --DetectAppLayerEventPrepare()
                    --DetectAppLayerEventSetupP2()"app-layer-events"阶段2
                  --SigBuildAddressMatchArray()   规则五元组变更为数组，以加速匹配
                  --DetectBufferRunSetupCallback()进一步构建检测类型环境
                    --DetectBufferType->SetupCallback()
                  --SignatureSetType()
                  --IPOnlySigParseAddress()       构建IPonly加速查找数据结构
        --SCSigRegisterSignatureOrderingFuncs()   注册规则优先级函数
        --SCSigOrderSignatures()                  按优先级排序规则列表
        --SCThresholdConfInitContext()            解析threshold.config文件
        --SigGroupBuild()          调整规则列表为运行时刻需要的结构
          --DetectSetFastPatternAndItsId()
          --SigInitStandardMpmFactoryContexts()
          --SigAddressPrepareStage1()
            --SignatureCreateMask()               计算规则标识，如 SIG_MASK_REQUIRE_PAYLOAD 等
            --RuleSetWhitelist()
            --DetectFlowbitsAnalyze()
          --SigAddressPrepareStage2()
            --RulesGroupByPorts()                 构建基于端口的规则组
            --IPOnlyPrepare()                     构建IPonly检测规则组
          --SigAddressPrepareStage3()
            --DetectEngineBuildDecoderEventSgh()  构建基于事件的规则组
          --SigAddressPrepareStage4()
            --PrefilterSetupRuleGroup()           构建规则组的prefilter多模环境
              --PatternMatchPrepareGroup()
                --MpmStorePrepareBuffer()
                  --MpmStoreSetup()
                    --PopulateMpmHelperAddPattern()
                    --mpm_table[].Prepare()
                --PrepareAppMpms()
                --PreparePktMpms()
              --sigmatch_table[].SetupPrefilter()
            --SigGroupHeadBuildNonPrefilterArray()汇总规则组的非prefilter的规则
          --DetectMpmPrepareBuiltinMpms()
          --DetectMpmPrepareAppMpms()             共享环境构建多模引擎
          --DetectMpmPreparePktMpms()
          --SigMatchPrepare()                     初始化单规则的检测引擎
          --VarNameStoreActivateStaging()         激活变量命名空间

    
    
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
从底层PCAP接收报文后，通过此函数处理L1-L4解码        
        
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
    --FlowGetFlowFromHash()
      --FlowGetNew()                 桶空/未找到则新建流
      --FlowCompare()                n元组匹配查找
      --TcpReuseReplace()            流重用
  --FlowUpdate()
    --FlowHandlePacketUpdate()     更新流表项
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

    
* 流管理线程
线程主函数"management" <==> ThreadVars->tm_func = TmThreadsManagement()
处理链"FlowManager" <==> tmm_modules[TMM_FLOWMANAGER]->Management = FlowManager()
    
--FlowManagerThreadSpawn()
  --TmThreadCreateMgmtThreadByName()
    --TmThreadCreate()             确定入口函数, TmThreadsManagement()
    --TmSlotSetFuncAppend()        确定槽函数, FlowManager()

    
--TmThreadsManagement()
  --FlowManagerThreadInit()
  --FlowManager()                  管理流/老化流入口
    --FlowUpdateSpareFlows()         0号线程，平衡空闲流表量
    --FlowTimeoutHash()              流老化
    --DefragTimeoutHash()            0号线程，老化其他hash表
    --HostTimeoutHash()
    --IPPairTimeoutHash()


* TCP流重组/应用协议识别
tcp协议上的应用层协议检测时，需要做数据重组
    
--SuricataMain()
  --PostConfLoadedSetup()
    --PreRunInit()
      --StreamTcpInitConfig()      TCP流重组初始化
        --StreamTcpReassembleInit()
        --FlowSetProtoFreeFunc()     注册 flow_freefuncs[]

    
--TmThreadsSlotPktAcqLoop()        PCAP入口函数
  --TmSlot->SlotThreadInit()
  -->FlowWorkerThreadInit()        初始化 TMM_FLOWWORKER 运行环境
    --StreamTcpThreadInit()        初始化流汇聚环境

    
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


* 基于规则的检测
--FlowWorker()
  --Detect()                    DetectEngineThreadCtx
    --DetectFlow()              基于流的检测
      --DetectRun()
    --DetectNoFlow()            无流检测
      --DetectRun()
        --DetectRunInspectIPOnly()   IPonly规则引擎, DetectEngineIPOnlyCtx->tree_ipv4src
          --IPOnlyMatchPacket()
        --DetectRunPrefilterPkt()    运行prefilters引擎
          --Prefilter()
        --DetectRulePacketRules()    运行逐报文规则, Signature->pkt_inspect
          --DetectEnginePktInspectionRun()
        --DetectRunTx()              运行事务检测
        --DetectRunPostRules()       检测后处理, 匹配Threshold规则，去掉部分告警
          --PacketAlertFinalize()
            --PacketAlertHandle()
              --PacketAlertHandle()
              --TagHandlePacket()
              --FlowSetHasAlertsFlag()


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


    
