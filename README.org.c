本文档介绍suricata主流程，以便于快速浏览
  1. 可参考单元测试 RunUnittests() 入口，了解环境初始化，以便于支持lib编译

--SuricataMain()
  --InitGlobal()
    --RunModeRegisterRunModes()    注册运行模式, runmodes[RUNMODE_PCAP_DEV]
  --ParseCommandLine()             解析命令行，赋值运行模式  SCInstance->run_mode
  --LoadYamlConfig()
  --SCLogLoadConfig()              初始化日志输出
    --SCLogInitLogModule()
  --PostConfLoadedSetup()
    --MpmTableSetup()              注册多模匹配算法, mpm_table[MPM_HS]
      --MpmHSRegister()
    --SpmTableSetup()              注册单模匹配算法, spm_table[SPM_HS]
      --SpmHSRegister()
    --AppLayerSetup()              应用层协议解析环境
      --AppLayerParserRegisterProtocolParsers()
      --AppLayerProtoDetectPrepareState()
    --SCHInfoLoadFromConfig()      加载主机os信息等，以更好的适配检测策略
    --SigTableSetup()              注册检测规则关键字, sigmatch_table[]
    --TmqhSetup()                  注册典型队列，用于线程间通信, tmqh_table[TMQH_SIMPLE]
    --RegisterAllModules()         注册、初始化线程模块, tmm_modules[]
    --TmModuleRunInit()
    --PreRunInit()
      --DefragInit()               IP重组初始化
      --FlowInitConfig()           流模块初始化
      --StreamTcpInitConfig()      TCP流重组初始化
  --PostConfLoadedDetectSetup()
    --DetectEngineCtxInit()        初始化检测引擎, DetectEngineCtx
    --LoadSignatures()             加载检测规则文件
  --RunModeDispatch()
    --RunModeGetCustomMode()       选择运行模型, runmodes[RUNMODE_PCAP_DEV]
    --RunMode->RunModeFunc()       运行模式初始化, RunModeIdsPcapWorkers()
    --FlowManagerThreadSpawn()
    --FlowRecyclerThreadSpawn()    启动流管理/回收线程

* 重要的全局变量
SCInstance suricata        全局环境数据
    

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
      --SRepInit()                                加载IP信誉库
      --SCClassConfLoadClassficationConfigFile()  解析 classification.config
      --SCRConfLoadReferenceConfigFile()          解析 reference.config
      --ActionInitConfig()                        初始化动作优先级, action_order_sigs[]
      --VarNameStoreSetupStaging()
    --LoadSignatures()             
      --SigLoadSignatures()
        --ProcessSigFiles()        加载检测规则文件, suricata.rules等
          --DetectLoadSigFile()
            --DetectEngineAppendSig()             解析检测规则, Signature
              --SigInit()
                --SigInitHelper()
                  --SigParse()
                    --SigParseBasics()
                    --SigParseOptions()           调用sigmatch_table[].Setup()
                  --DetectAppLayerEventPrepare()
                    --DetectAppLayerEventSetupP2()"app-layer-events"阶段2
                  --SigBuildAddressMatchArray()
        --SCSigRegisterSignatureOrderingFuncs()   注册规则优先级函数
        --SCSigOrderSignatures()                  按优先级排序规则列表
        --SCThresholdConfInitContext()            解析threshold.config文件
        --SigGroupBuild()          调整规则列表为运行时刻需要的结构

    
    
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
    --DecodePcapThreadInit()
    --FlowWorkerThreadInit()          初始化 TMM_FLOWWORKER 运行环境
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
    
--TmThreadsManagement()
  --FlowManagerThreadInit()
  --FlowManager()                  管理流/老化流入口
    --FlowUpdateSpareFlows()         0号线程，平衡空闲流表量
    --FlowTimeoutHash()              流老化
    --DefragTimeoutHash()            0号线程，老化其他hash表
    --HostTimeoutHash()
    --IPPairTimeoutHash()


* TCP流重组
tcp协议上的应用层协议检测时，需要做数据重组
    
--SuricataMain()
  --PostConfLoadedSetup()
    --PreRunInit()
      --StreamTcpInitConfig()      TCP流重组初始化
        --StreamTcpReassembleInit()
        --FlowSetProtoFreeFunc()     注册 flow_freefuncs[]

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
    --StreamTcpReassembleAppLayer()                 应用识别
      --ReassembleUpdateAppLayer()
        --AppLayerHandleTCPData()
          --TCPProtoDetect()
            --AppLayerProtoDetectGetProto()         基于规则、端口的协议识别
            --AppLayerParserParse()                 协议解析
          --AppLayerParserParse()
  --StreamTcpReassembleHandleSegmentHandleData()    缓存数据, TcpStream
    --StreamTcpReassembleInsertSegment()
      --DoInsertSegment()
      --InsertSegmentDataCustom()
  --StreamTcpReassembleAppLayer()
