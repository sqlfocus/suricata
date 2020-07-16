本文档介绍suricata主流程，以便于快速浏览

--SuricataMain()
  --PostConfLoadedSetup()
    --RegisterAllModules()         注册线程模块, tmm_modules[]
    --PreRunInit()
      --DefragInit()
      --FlowInitConfig()           流模块初始化
      --StreamTcpInitConfig()
  --RunModeDispatch()
    --RunModeGetCustomMode()       选择运行模型, runmodes[RUNMODE_PCAP_DEV]
    --RunMode->RunModeFunc()       运行模式初始化, RunModeIdsPcapWorkers()
    --FlowManagerThreadSpawn()
    --FlowRecyclerThreadSpawn()    启动流管理/回收线程

    
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
    --FlowWorkerThreadInit()
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
  --FlowUpdate()                   更新流
    --FlowHandlePacketUpdate()
  --------TCP处理-------
  --StreamTcp()                    流汇聚
  --Detect()                       流检测
  --------UDP处理-------
  --AppLayerHandleUdp()

    
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

