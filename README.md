编译：

之前是通过使用Delphi7开发和编译。



介绍：

    本软件利用ARP请求原理及多线程扫描，可快速扫描所有IP设备，可将结果存档，用来高效统计局域网在线用户／离线，当网络主机MAC地址发生变化时还会有提示．
还有网络唤醒功能可以远程开机!

特点：
    本软件使用KOL库(NB俄国佬用汇编写的)编写体积小，速度快．


主界面：
    第一个输入框为开始IP
    第二个输入框为结束IP(其实两者也可以互换)
    第三个输入框有两种作用:
        当扫描IP时,这里是用来设置扫描IP的线程数,设为0则线程数等于将要扫描的IP数(最大线程999)。
        当网络唤醒时,这里是设置唤醒每台机器后间隔的时间(毫秒)。
    按钮“开始”点击开始扫描;
    按钮“清空”点击则清空下面的列表;


右键菜单:
    “唤醒”向列表中选中的主机发送唤醒魔法包。
    “保存”可以将IP-MAC列表存档,“载入”则将存档的IP-MAC列表载入到列表。
    “删除”删除列表中选中项。

备注编辑
    保存扫描列表后，直接用记事本编辑IpMac.txt。格式为 “IP=MAC|备注”

更新日志：
```
2010-06-23 v1.2e
    % 修复在中途离线IP仍然显示为在线的BUG（因ARP缓存导致）

2010-06-13 v1.2d
    + 支持IP备注

2010-05-29 v1.2c
    % 列表保存BUG修复，并加入覆盖提示
    + 增加扫描已列表选项
    % 修复跨网段BUG
    % 修复多线程潜在的死锁BUG
    * 改进列表存储

2010-01-12
    * 配置文件路径一点小改变

2009-11-25 v1.2      
    + 加入新增IP标识
    + 加入IP段设置保存功能(一个用户提出)
    * 内部做了些小优化,也减小了内存占用(本来就不高)

2009-4-21 v1.1
    * 在1.0的基础上对很多细节进行优化。
    + 加入IP和MAC采集存档,及MAC地址变更提示和在线主机显示。
    + 加入唤醒延时和对线程进行限制
    * 对取机器号算法改进，再无例外情况
    ...

2009-4-19 v1.0
    + 实现IP-MAC多线程扫描和网络唤醒功能。 
```

