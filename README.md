# BXC_gb28181Client
* @author 北小菜 
* 个人主页地址：https://space.bilibili.com/487906612
* 项目的视频教程地址：https://www.bilibili.com/video/BV1cK411z73C

## 介绍
1. 一个基于C++开发支持国标GB28181协议的摄像头模拟软件。
2. BXC_gb28181Client可作为支持国标GB28181协议的摄像头模拟软件，用于向信令服务器注册，注册完成后，
一方面主动定时发送keepalive的Message请求体，用于传输层的保活检测，另一方面被动接收
信令服务器的Invite请求，一旦接收到Invite请求，则回复Invite请求并携带SDP相关信息。
信令服务器收到后，主动发送ACK请求，BXC_gb28181Client收到信令服务器的ACK请求后，开始通过RTP推送ps流到国标流媒体服务器。
BXC_gb28181Client收到信令服务器的BYE请求后，需要结束RTP推送ps流。

## BXC_gb28181Client介绍
1. 基于osip和exosip开源库，开发的国标GB28181流媒体信令服务器
2. osip和exosip版本一定要对应，否则可能会出现不兼容的情况。我经常用的版本osip2-5.1.2和exosip2-5.1.2，
* windows系统编译还需要c-ares库

#### 附3个库的官方下载地址：
~~~
  osip:   http://ftp.twaren.net/Unix/NonGNU/osip/
  exosip: http://download.savannah.gnu.org/releases/exosip/
  c-ares: https://c-ares.haxx.se/
~~~



## 快速开始

#### linxu系统编译运行
~~~

一，首先安装osip和exosip，建议按照上面的BXC_gb28181Client介绍下载我推荐的 osip2-5.1.2和exosip2-5.1.2

1. 编译安装 osip2-5.1.2
 cd osip2-5.1.2  
 ./configure
 make
 sudo make install
 
2. 编译安装 exosip2-5.1.2
 cd exosip2-5.1.2
 ./configure
 make
 sudo make install
 
二，开始安装 BXC_gb28181Client
1. 下载代码
 git clone https://gitee.com/Vanishi/BXC_gb28181Client.git
2. 编译
 cd BXC_gb28181Client
 mkdir build
 cd build
 cmake ..
 make 
3. 运行
 ./BXC_gb28181Client
 
 
~~~
### windows系统编译运行
~~~

一，osip和exosip编译到windows平台比较麻烦，我也是在编译过程中解决了多个报错，用了大半天时间，才编译出可用的版本

如果你在windows平台自行编译osip和exosip，还需要编译c-ares库。推荐使用 c-ares-1.16.0 配合 osip2-5.1.2 和 exosip2-5.1.2

我已经将上面3个库编译好放在了3rdparty，并提供了 vs2019/x64/Debug 和 vs2019/x64/Release

二，只需要使用vs2019打开 BXC_gb28181Client.sln
选择 x64/Debug 或 x64/Release就能直接运行，依赖库都配置了相对路径
 
~~~


## 常见问题

1. 常见报错 error while loading shared libraries: libXXX.so.X: cannot open shared object file: No such file [解决方法](https://blog.csdn.net/deeplan_1994/article/details/83927832)






