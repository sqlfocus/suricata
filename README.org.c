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
    --RunMode->RunModeFunc()       模式初始化,
    --FlowManagerThreadSpawn()
    --FlowRecyclerThreadSpawn()    启动流管理/回收线程



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

