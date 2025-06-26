//
// Created by bxc on 2022/12/13.
//

#include "SipClient.h"
#include "SipServerConfig.h"
#include "Utils/Log.h"
using namespace BXC;


int main(int argc, char *argv[]) {
    LOGI("");

    srand((int)time(NULL));   //每次执行种子不同，生成不同的随机数

    // 公网测试配置
    // const char *serverIp = "60.205.164.47";
    // int serverPort = 5060;
    // const char *serverSipId = "10000000002000000001";
    // const char *serverSipRealm = "1000000000"; // sip域
    // const char *serverSipPass = "123456";
    // int serverSipTimeout = 0;
    // int serverSipExpiry = 3600;

    // const char *clientUa = "BXC_gb28181Client";
    // const char *clientIp = "127.0.0.1";
    // int clientPort = 5060;
    // const char *clientId = "10000000001321008023";
    // int localRtpPort = 34784;// 本地RTP的推流端口
    

    // 物联网平台配置
    const char *serverIp = "10.164.220.149";
    int serverPort = 5060;
    const char *serverSipId = "34020000002000000001";
    const char *serverSipRealm = "3402000000"; // sip域
    const char *serverSipPass = "SyY*4751";
    int serverSipTimeout = 0;
    int serverSipExpiry = 3600;

    const char *clientUa = "BXC_gb28181Client";
    const char *clientIp = "10.23.2.186";
    int clientPort = 5060;
    const char *clientId = "52010050441324300100";
    int localRtpPort = 34784;// 本地RTP的推流端口

    SipServerConfig serverConfig(serverIp,serverPort,serverSipId,serverSipRealm,serverSipPass,serverSipTimeout,serverSipExpiry);
    SipClientConfig clientConfig(clientUa,clientIp,clientPort,clientId,localRtpPort);

    SipClient client(&serverConfig,&clientConfig);
    client.loop();

    return 0;
}