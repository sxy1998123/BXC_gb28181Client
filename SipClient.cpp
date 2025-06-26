//
// Created by bxc on 2022/12/13.
//

#include "SipClient.h"
#include <stdio.h>
#include <string.h>

#include "Utils/Log.h"
#include "Utils/Utils.h"
#include "SipServerConfig.h"

#ifndef WIN32
// Linux系统
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif // !WIN32

extern "C"
{
#include "Utils/HTTPDigest.h"
}

#include <openssl/md5.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

namespace BXC
{
    // 生成 Authorization 头（MD5 算法）
    void build_authorization_header(
        const char *username,
        const char *password,
        const char *method, // 例如 "REGISTER"
        const char *realm,
        const char *nonce,
        const char *uri,   // 例如 "sip:31011500991320000001@192.168.1.100"
        char *auth_header, // 输出缓冲区
        size_t buffer_size)
    {
        // 生成 HA1 = MD5(username:realm:password)
        unsigned char ha1[MD5_DIGEST_LENGTH];
        char ha1_input[256];
        snprintf(ha1_input, sizeof(ha1_input), "%s:%s:%s", username, realm, password);
        MD5((unsigned char *)ha1_input, strlen(ha1_input), ha1);

        // 生成 HA2 = MD5(method:uri)
        unsigned char ha2[MD5_DIGEST_LENGTH];
        char ha2_input[256];
        snprintf(ha2_input, sizeof(ha2_input), "%s:%s", method, uri);
        MD5((unsigned char *)ha2_input, strlen(ha2_input), ha2);

        // 生成 Response = MD5(HA1:nonce:HA2)
        char response_input[128];
        snprintf(response_input, sizeof(response_input),
                 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:" // HA1
                 "%s:"                                                               // nonce
                 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", // HA2
                 ha1[0], ha1[1], ha1[2], ha1[3], ha1[4], ha1[5], ha1[6], ha1[7],
                 ha1[8], ha1[9], ha1[10], ha1[11], ha1[12], ha1[13], ha1[14], ha1[15],
                 nonce,
                 ha2[0], ha2[1], ha2[2], ha2[3], ha2[4], ha2[5], ha2[6], ha2[7],
                 ha2[8], ha2[9], ha2[10], ha2[11], ha2[12], ha2[13], ha2[14], ha2[15]);

        unsigned char response[MD5_DIGEST_LENGTH];
        MD5((unsigned char *)response_input, strlen(response_input), response);

        // 构造 Authorization 头
        snprintf(auth_header, buffer_size,
                 "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", "
                 "response=\"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\", "
                 "algorithm=MD5",
                 username, realm, nonce, uri,
                 response[0], response[1], response[2], response[3],
                 response[4], response[5], response[6], response[7],
                 response[8], response[9], response[10], response[11],
                 response[12], response[13], response[14], response[15]);
    }

    // 写回调函数，处理接收到的数据
    static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
    {
        size_t realsize = size * nmemb;
        struct HttpResponse *mem = (struct HttpResponse *)userp;

        char *ptr = (char *)realloc(mem->HttpResponse, mem->size + realsize + 1);
        if (!ptr)
        {
            fprintf(stderr, "内存不足 (realloc返回NULL)\n");
            return 0;
        }

        mem->HttpResponse = ptr;
        memcpy(&(mem->HttpResponse[mem->size]), contents, realsize);
        mem->size += realsize;
        mem->HttpResponse[mem->size] = 0;

        return realsize;
    }
    // curl请求ZLMediaKit 开始推流
    int curl_start_rtp(BXC::SdpTrack sdp,SipClientConfig *clientConfig)
    {
        CURL *curl = curl_easy_init();
        if (!curl)
        {
            fprintf(stderr, "Failed to initialize CURL\n");
            return -1;
        }

        // 编码参数
        char *encoded_dst_url = curl_easy_escape(curl, sdp.peerIp, 0);

        // 计算 URL 长度
        size_t url_len = snprintf(NULL, 0,
                                  "http://127.0.0.1/index/api/startSendRtp?"
                                  "secret=zrlSu7Fl4TTtLCDKoG04wzwf0yN8ilit&"
                                  "vhost=__defaultVhost__&"
                                  "app=live&"
                                  "stream=stream&"
                                  "src_port=%d&"
                                  "ssrc=%d&"
                                  "dst_url=%s&"
                                  "dst_port=%d&"
                                  "is_udp=0",
                                  clientConfig->localRtpPort,sdp.ssrc, encoded_dst_url, sdp.peerRtpPort) +
                         1;

        // 分配内存
        char *url = (char *)malloc(url_len);
        if (!url)
        {
            // 构造失败
            fprintf(stderr, "Memory allocation failed\n");
            curl_free(encoded_dst_url);
            curl_easy_cleanup(curl);
            return -1;
        }

        // 构造最终 URL
        snprintf(url, url_len,
                 "http://127.0.0.1/index/api/startSendRtp?"
                 "secret=zrlSu7Fl4TTtLCDKoG04wzwf0yN8ilit&"
                 "vhost=__defaultVhost__&"
                 "app=live&"
                 "stream=stream&"
                 "src_port=%d&"
                 "ssrc=%d&"
                 "dst_url=%s&"
                 "dst_port=%d&"
                 "is_udp=0",
                 clientConfig->localRtpPort,sdp.ssrc, encoded_dst_url, sdp.peerRtpPort);

        LOGI("start url:%s", url);

        struct HttpResponse chunk;
        // 初始化响应内存结构体
        chunk.HttpResponse = (char *)malloc(1);
        chunk.size = 0;

        // 设置 CURL 选项
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); // 5秒超时
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);                        // 详细日志
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); // 回调函数
        // 执行HTTP请求
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl请求失败: %s\n", curl_easy_strerror(res));
        }
        else
        {
            // 解析JSON
            cJSON *json = cJSON_Parse(chunk.HttpResponse);
            if (!json)
            {
                const char *error_ptr = cJSON_GetErrorPtr();
                if (error_ptr)
                {
                    fprintf(stderr, "JSON解析错误: %s\n", error_ptr);
                }
            }
            else
            {
                auto json_string = cJSON_Print(json);
                LOGI("ZLMediaKit Response:\r\n %s",json_string);
                // 释放cJSON对象
                cJSON_Delete(json);
            }
        }

        // 清理资源
        curl_free(encoded_dst_url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // curl请求ZLMediaKit 结束推流
    int curl_stop_rtp()
    {
        CURL *curl = curl_easy_init();
        if (!curl)
        {
            fprintf(stderr, "Failed to initialize CURL\n");
            return -1;
        }

        // 计算 URL 长度
        size_t url_len = snprintf(NULL, 0,
                                  "http://127.0.0.1/index/api/stopSendRtp?secret=zrlSu7Fl4TTtLCDKoG04wzwf0yN8ilit&vhost=__defaultVhost__&app=live&stream=stream") +
                         1;

        // 分配内存
        char *url = (char *)malloc(url_len);
        if (!url)
        {
            // 构造失败
            fprintf(stderr, "Memory allocation failed\n");
            curl_easy_cleanup(curl);
            return -1;
        }

        // 构造最终 URL
        snprintf(url, url_len,
                "http://127.0.0.1/index/api/stopSendRtp?secret=zrlSu7Fl4TTtLCDKoG04wzwf0yN8ilit&vhost=__defaultVhost__&app=live&stream=stream");

        LOGI("stop url:%s", url);

        struct HttpResponse chunk;
        // 初始化响应内存结构体
        chunk.HttpResponse = (char *)malloc(1);
        chunk.size = 0;

        // 设置 CURL 选项
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); // 5秒超时
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);                        // 详细日志
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); // 回调函数
        // 执行HTTP请求
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl请求失败: %s\n", curl_easy_strerror(res));
        }
        else
        {
            // 解析JSON
            cJSON *json = cJSON_Parse(chunk.HttpResponse);
            if (!json)
            {
                const char *error_ptr = cJSON_GetErrorPtr();
                if (error_ptr)
                {
                    fprintf(stderr, "JSON解析错误: %s\n", error_ptr);
                }
            }
            else
            {
                auto json_string = cJSON_Print(json);
                LOGI("ZLMediaKit Response:\r\n %s",json_string);
                // 释放cJSON对象
                cJSON_Delete(json);
            }
        }

        curl_easy_cleanup(curl);
        return 0;
    }

    SipClient::SipClient(SipServerConfig *serverConfig, SipClientConfig *clientConfig)
        : mServerConfig(serverConfig), mClientConfig(clientConfig),
          mRegistered(false), mRegisterId(-1)
    {

#ifdef WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            LOGE("WSAStartup Error");
            return;
        }
#endif // WIN32
    }
    SipClient::~SipClient()
    {

#ifdef WIN32
        WSACleanup();
#endif // WIN32
    }

    void SipClient::loop()
    {

        if (this->init_sip_client() != 0)
        {
            return;
        }

        SipClient *sipClient = this;
        static bool allowReg = true;

        int64_t lastKeepaliveTimestamp = 0;
        int64_t curTimestamp = 0;
        int64_t interval = 3000; // 客户端发送keepalive检测的间隔，单位：毫秒

        while (!sipClient->mClientConfig->quit)
        {

            // 首次发起注册
            if (allowReg && !sipClient->mRegistered)
            {
                allowReg = false;
                sipClient->request_register();
            }

            // 心跳机制 start （开发过程中，为防止影响抓包，可以先注释）
            // if (sipClient->mRegistered)
            // {
            //     curTimestamp = getCurTimestamp();
            //     if (lastKeepaliveTimestamp == 0)
            //     {
            //         lastKeepaliveTimestamp = curTimestamp;
            //     }
            //     else
            //     {
            //         if ((curTimestamp - lastKeepaliveTimestamp) > interval)
            //         {
            //             sipClient->request_message_keepalive();
            //             lastKeepaliveTimestamp = curTimestamp;
            //         }
            //     }
            // }
            // 心跳机制 end

            eXosip_event_t *evtp = eXosip_event_wait(sipClient->mSipCtx, 0, 20);
            if (!evtp)
            {
                eXosip_automatic_action(sipClient->mSipCtx);
                osip_usleep(100000);
                continue;
            }

            // 失败时自动重连
            eXosip_automatic_action(sipClient->mSipCtx);
            sipClient->sip_event_handle(evtp);
            eXosip_event_free(evtp); // 释放
        }
    }

    int SipClient::init_sip_client()
    {

        mSipCtx = eXosip_malloc();
        if (!mSipCtx)
        {
            LOGE("new uas context error");
            return -1;
        }
        if (eXosip_init(mSipCtx))
        {
            LOGE("exosip init error");
            return -1;
        }
        // if (eXosip_listen_addr(mSipCtx, IPPROTO_UDP, NULL, mClientConfig->port, AF_INET, 0))
        if (eXosip_listen_addr(mSipCtx, IPPROTO_TCP, NULL, mClientConfig->port, AF_INET, 0))
        {
            LOGE("listen error");
            return -1;
        }
        eXosip_set_user_agent(mSipCtx, mClientConfig->ua);
        if (eXosip_add_authentication_info(mSipCtx, mClientConfig->id, mClientConfig->id, mServerConfig->getSipPass(), NULL, NULL) < 0)
        {
            LOGI("eXosip_add_authentication_info error");
            return -1;
        }

        return 0;
    }
    int SipClient::request_message_keepalive()
    {
        char from[1024] = {0};
        char to[1024] = {0};

        sprintf(from, "sip:%s@%s:%d", mClientConfig->id, mClientConfig->ip, mClientConfig->port);
        sprintf(to, "sip:%s@%s:%d", mServerConfig->getSipId(), mServerConfig->getIp(), mServerConfig->getPort());

        osip_message_t *msg;
        char body[1024] = {0};

        sprintf(
            body,
            "<?xml version=\"1.0\" encoding=\"GB2312\" standalone=\"yes\" ?>\r\n"
            "<Notify>\r\n"
            "<CmdType>Keepalive</CmdType>\r\n"
            "<SN>1</SN>\r\n"
            "<DeviceID>%s</DeviceID>\r\n"
            "<Status>OK</Status>\r\n"
            "</Notify>\r\n",
            mClientConfig->id);

        eXosip_message_build_request(mSipCtx, &msg, "MESSAGE", to, from, NULL);
        osip_message_set_body(msg, body, strlen(body));
        osip_message_set_content_type(msg, "Application/MANSCDP+xml");
        eXosip_message_send_request(mSipCtx, msg);

        //        char *s;
        //        size_t len;
        //        osip_message_to_str(msg, &s, &len);
        //         LOGI("send cmd catalog: \n%s", s);

        return 0;
    }

    int SipClient::request_message_catalog(int SN)
    {
        char from[1024] = {0};
        char to[1024] = {0};

        sprintf(from, "sip:%s@%s:%d", mClientConfig->id, mClientConfig->ip, mClientConfig->port);
        sprintf(to, "sip:%s@%s:%d", mServerConfig->getSipId(), mServerConfig->getIp(), mServerConfig->getPort());

        osip_message_t *msg;
        char body[1024] = {0};
        char *s;
        size_t len;

        sprintf(
            body,
            // "<?xml version=\"1.0\"?>\r\n"
            // "<Response>\r\n"
            // "  <CmdType>Catalog</CmdType>\r\n"
            // "  <SN>%d</SN>\r\n"
            // "  <DeviceID>%s</DeviceID>\r\n"
            // "  <SumNum>1</SumNum>\r\n"
            // "  <DeviceList Num=\"1\">\r\n"
            // "    <Item>\r\n"
            // "      <DeviceID>5201005044132430000</DeviceID>\r\n"
            // "      <Name>ZedCamera</Name>\r\n"
            // "      <Manufacturer>TSINGSEE</Manufacturer>\r\n"
            // "      <Model>BXC_GB28181client</Model>\r\n"
            // "      <Owner>Owner</Owner>\r\n"
            // "      <CivilCode>52010000000</CivilCode>\r\n"
            // "      <Address>Address</Address>\r\n"
            // "      <Parental>0</Parental>\r\n"
            // "      <ParentID>%s</ParentID>\r\n"
            // "      <RegisterWay>1</RegisterWay>"
            // "      <Status>ON</Status>\r\n"
            // "    </Item>\r\n"
            // "  </DeviceList>\r\n"
            // "</Response>\r\n",
            "<?xml version=\"1.0\"?>\r\n"
            "<Response>\r\n"
            "<CmdType>Catalog</CmdType>\r\n"
            "<SN>%d</SN>\r\n"
            "<DeviceID>%s</DeviceID>\r\n"
            "<SumNum>1</SumNum>\r\n"
            "<DeviceList Num=\"1\">\r\n"
            "<Item>\r\n"
            "<DeviceID>52010050441324300100</DeviceID>\r\n"
            "<Name>ZedCamera</Name>\r\n"
            "<Manufacturer>TSINGSEE</Manufacturer>\r\n"
            "<Model>BXC_GB28181client</Model>\r\n"
            "<Owner>Owner</Owner>\r\n"
            "<CivilCode>5201000000</CivilCode>\r\n"
            "<Address>Address</Address>\r\n"
            "<Parental>0</Parental>\r\n"
            "<ParentID>52010050441324300100</ParentID>\r\n"
            "<RegisterWay>1</RegisterWay>\r\n"
            "<Status>ON</Status>\r\n"
            "</Item>\r\n"
            "</DeviceList>\r\n"
            "</Response>\r\n",
            SN,
            // mServerConfig->getSipId(),
            // mServerConfig->getSipId()
            mClientConfig->id
            // mClientConfig->id
            );
       
        LOGI("res_catalog_body->body: %s", body);

        eXosip_message_build_request(mSipCtx, &msg, "MESSAGE", to, from, NULL);
        osip_message_set_body(msg, body, strlen(body));
        osip_message_set_content_type(msg, "Application/MANSCDP+xml");
        eXosip_message_send_request(mSipCtx, msg);

        osip_message_to_str(msg, &s, &len);
        // LOGI("send cmd catalog: \n%s", s);

        return 0;
    }
    int SipClient::request_message_DeviceStatus(int SN)
    {
        char from[1024] = {0};
        char to[1024] = {0};

        sprintf(from, "sip:%s@%s:%d", mClientConfig->id, mClientConfig->ip, mClientConfig->port);
        sprintf(to, "sip:%s@%s:%d", mServerConfig->getSipId(), mServerConfig->getIp(), mServerConfig->getPort());

        osip_message_t *msg;
        char body[1024] = {0};
        char *s;
        size_t len;

        sprintf(
            body,
            "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n"
            "<Response>\r\n"
            "  <CmdType>DeviceStatus</CmdType>\r\n"
            "  <SN>%d</SN>\r\n"
            "  <DeviceID>%s</DeviceID>\r\n"
            "  <Result>OK</Result>\r\n"
            "  <Online>online</Online>\r\n"
            "  <Status>OK</Status>\r\n"
            "  <EncodeStatus>OK</EncodeStatus>\r\n"
            "  <RecordStatus>OFF</RecordStatus>\r\n"
            "</Response>",
            SN,
            mClientConfig->id
            );

        eXosip_message_build_request(mSipCtx, &msg, "MESSAGE", to, from, NULL);
        osip_message_set_body(msg, body, strlen(body));
        osip_message_set_content_type(msg, "Application/MANSCDP+xml");
        eXosip_message_send_request(mSipCtx, msg);

        osip_message_to_str(msg, &s, &len);
        // LOGI("send cmd catalog: \n%s", s);

        return 0;
    }
    int SipClient::request_message_DeviceInfo(int SN)
    {
        char from[1024] = {0};
        char to[1024] = {0};

        sprintf(from, "sip:%s@%s:%d", mClientConfig->id, mClientConfig->ip, mClientConfig->port);
        sprintf(to, "sip:%s@%s:%d", mServerConfig->getSipId(), mServerConfig->getIp(), mServerConfig->getPort());

        osip_message_t *msg;
        char body[1024] = {0};
        char *s;
        size_t len;

        sprintf(
            body,
            "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n"
            "<Response>\r\n"
            "  <CmdType>DeviceInfo</CmdType>\r\n"
            "  <SN>%d</SN>\r\n"
            "  <DeviceID>%s</DeviceID>\r\n"
            "  <Result>OK</Result>\r\n"
            "  <DeviceName>IPC-123</DeviceName>\r\n"
            "  <Manufacturer>test</Manufacturer>\r\n"
            "  <Model>IPC-HDW5431</Model>\r\n"
            "  <Firmware>V2.1.0</Firmware>\r\n"
            "  <Channel>1</Channel>\r\n"
            "</Response>",
            SN,
            mServerConfig->getSipId());

        eXosip_message_build_request(mSipCtx, &msg, "MESSAGE", to, from, NULL);
        osip_message_set_body(msg, body, strlen(body));
        osip_message_set_content_type(msg, "Application/MANSCDP+xml");
        eXosip_message_send_request(mSipCtx, msg);

        osip_message_to_str(msg, &s, &len);
        // LOGI("send cmd catalog: \n%s", s);

        return 0;
    }
    int SipClient::request_register()
    {
        int ret = -1;
        osip_message_t *msg = NULL;
        char from[1024] = {0};
        char contact[1024] = {0};
        char proxy[1024] = {0};

        if (mRegistered)
        { // refresh register
            LOGI("刷新注册 mRegisterId=%d", mRegisterId);

            ret = eXosip_register_build_register(mSipCtx, mRegisterId, mServerConfig->getSipExpiry(), &msg);
            if (!ret)
            {
                LOGE("eXosip_register_build_register error: ret=%d", ret);
                return -1;
            }
        }
        else
        { // new register
            LOGI("未注册 mRegisterId=%d", mRegisterId);

            sprintf(from, "sip:%s@%s:%d", mClientConfig->id, mClientConfig->ip, mClientConfig->port);
            sprintf(proxy, "sip:%s@%s:%d", mServerConfig->getSipId(), mServerConfig->getIp(), mServerConfig->getPort());
            sprintf(contact, "sip:%s@%s:%d", mClientConfig->id, mClientConfig->ip, mClientConfig->port);
            mRegisterId = eXosip_register_build_initial_register(mSipCtx, from, proxy, contact, mServerConfig->getSipExpiry(), &msg);
            if (mRegisterId <= 0)
            {
                LOGE("eXosip_register_build_initial_register error: mRegisterId=%d", mRegisterId);
                return -1;
            }
        }
        ret = eXosip_register_send_register(mSipCtx, mRegisterId, msg);
        if (ret)
        {
            LOGE("eXosip_register_send_register error: ret=%d", ret);
            return ret;
        }

        char *msg_str;
        size_t msg_strlen;
        osip_message_to_str(msg, &msg_str, &msg_strlen);
        LOGI("注册请求体: %s", msg_str);
        return ret;
    }
    int SipClient::response_message_answer(eXosip_event_t *evtp, int code)
    {

        osip_message_t *msg = nullptr;
        int returnCode = eXosip_message_build_answer(mSipCtx, evtp->tid, code, &msg);

        if (returnCode == 0 && msg)
        {
            eXosip_lock(mSipCtx);
            eXosip_message_send_answer(mSipCtx, evtp->tid, code, msg);
            eXosip_unlock(mSipCtx);
            //        osip_message_free(msg);
        }
        else
        {
            bool msg_state = false;
            if (msg)
            {
                msg_state = true;
            }
            LOGE("error: code=%d,returnCode=%d,msg=%d", code, returnCode, msg_state);
        }

        return 0;
    }
    int SipClient::response_message(eXosip_event_t *evtp)
    {

        osip_body_t *req_body = nullptr;
        osip_message_get_body(evtp->request, 0, &req_body);
        LOGI("req_body->body: %s", req_body->body);

        char cmd[64] = {0};
        parse_xml(req_body->body, "<CmdType>", false, "</CmdType>", false, cmd);
        LOGI("got message: %s", cmd);

        char SN_c[20] = {0};              // 序列号
        int SN = 0;                       // 序列号
        char DeviceID[100] = {0};         // 设备编码
        char DecoderChannelID[100] = {0}; // 解码器通道编码
        char PlayUrl[512] = {0};          // 源视频地址

        parse_xml(req_body->body, "<SN>", false, "</SN>", false, SN_c);
        parse_xml(req_body->body, "<DeviceID>", false, "</DeviceID>", false, DeviceID);
        parse_xml(req_body->body, "<DecoderChannelID>", false, "</DecoderChannelID>", false, DecoderChannelID);
        parse_xml(req_body->body, "<PlayUrl>", false, "</PlayUrl>", false, PlayUrl);
  
        // LOGI("SN_c:%s", SN_c);
        // LOGI("DeviceID:%s", DeviceID);
        // LOGI("DecoderChannelID:%s", DecoderChannelID);
        SN = std::stoi(SN_c);

        if (strcmp(cmd, "Catalog") == 0)
        {
            // LOGI("handle message: %s", cmd);
            this->response_message_answer(evtp, 200);
            this->request_message_catalog(SN);
        }
        else if (strcmp(cmd, "DeviceStatus") == 0)
        {
            this->response_message_answer(evtp, 200);
            this->request_message_DeviceStatus(SN);
        }
        else if (strcmp(cmd, "DeviceInfo") == 0)
        {
            this->response_message_answer(evtp, 200);
            this->request_message_DeviceInfo(SN);
        }
        else
        {
            this->response_message_answer(evtp, 200);
        }

        return 0;
    }
    int SipClient::response_invite(eXosip_event_t *evtp)
    {
        char *username = evtp->request->to->url->username; // 对应摄像头的DeviceID
        char *CallID = evtp->request->call_id->number;
        LOGI("username:%s", username);
        LOGI("CallID:%s", CallID);

        osip_message_t *answer = nullptr;
        eXosip_lock(mSipCtx);
        eXosip_call_send_answer(mSipCtx, evtp->tid, 180, nullptr);
        int ret = eXosip_call_build_answer(mSipCtx, evtp->tid, 200, &answer);
        if (ret != 0)
        {
            eXosip_call_send_answer(mSipCtx, evtp->tid, 400, nullptr);
            LOGE("camera: %s eXosip_call_build_answer error", username);
        }
        else
        {

            // 采用exosip的函数解析sdp

            // printf("-----------exosip parse start-----------\n");
            // sdp_message_t *remote_sdp = eXosip_get_remote_sdp(mSipCtx, evtp->did);
            // if (remote_sdp)
            // {
            //     sdp_media_t *video_sdp = eXosip_get_video_media(remote_sdp);
            //     if (video_sdp)
            //     {
            //         int pos = 0;
            //         char *video_port = video_sdp->m_port; // audio_port
            //         for (int i = 0; i < video_sdp->a_attributes.nb_elt; i++)
            //         {
            //             sdp_attribute_t *attr = (sdp_attribute_t *)osip_list_get(&video_sdp->a_attributes, i);
            //             printf("1-%s : %s\n", attr->a_att_field, attr->a_att_value);
            //         }
            //         while (!osip_list_eol(&(remote_sdp->a_attributes), pos))
            //         {
            //             sdp_attribute_t *at;
            //             at = (sdp_attribute_t *)osip_list_get(&remote_sdp->a_attributes, pos);
            //             printf(
            //                 "2-%s : %s\n", at->a_att_field,
            //                 at->a_att_value); // 这里解释了为什么在SDP消息体中属性a里面存放必须是两列
            //             pos++;
            //         }
            //         while (!osip_list_eol(&(remote_sdp->m_medias), pos))
            //         {
            //             sdp_attribute_t *at;

            //             at = (sdp_attribute_t *)osip_list_get(&remote_sdp->m_medias, pos);
            //             printf(
            //                 "3-%s : %s\n", at->a_att_field,
            //                 at->a_att_value); // 这里解释了为什么在SDP消息体中属性a里面存放必须是两列

            //             pos++;
            //         }
            //     }
            // }
            // printf("-----------exosip parse end-----------\n");

            printf("-----------my parse start-----------\n");
            int trackSize = 0;
            // 下面解析SDP的方式只适合一个媒体流，所有如果同时包含音频和视频流，需要注意！！！
            // 采用自定义的方式解析sdp
            osip_body_t *req_body = nullptr;
            osip_message_get_body(evtp->request, 0, &req_body);

            std::vector<std::string> lineArray = split(req_body->body, "\n");
            for (auto &line : lineArray)
            {
                printf(">>>>>>%s\n", line.data());

                if (!strncmp(line.data(), "c=IN", strlen("c=IN")))
                {
                    // example: c=IN IP4 192.168.8.91
                    if (sscanf(line.data(), "c=IN IP4 %39s ", this->mSdpTrack.peerIp) != 1)
                    {
                        LOGE("parse line error:%s", line.data());
                        break;
                    }
                }
                if (!strncmp(line.data(), "m=", strlen("m=")))
                {
                    // example: m=video 15060 TCP/RTP/AVP 96
                    if (sscanf(line.data(), "m=%9s %d %19s %39s ", this->mSdpTrack.mediaType, &this->mSdpTrack.peerRtpPort, this->mSdpTrack.peerRtpTransProtocol, this->mSdpTrack.peerStreamType) != 4)
                    {
                        LOGE("parse line error:%s", line.data());
                        break;
                    }
                    else
                    {
                        // success
                        trackSize++;
                    }
                }
                if (!strncmp(line.data(), "y=", strlen("y=")))
                {
                    // example: y=0018023001
                    if (sscanf(line.data(), "y=%s", &(this->mSdpTrack).ssrc_s) != 1)
                    {
                        LOGE("parse line error:%s", line.data());
                        break;
                    } else {
                        // 解析正常
                        sscanf(this->mSdpTrack.ssrc_s,"%d", &this->mSdpTrack.ssrc);
                    }
                }
            }
            printf("\r\n");
            LOGI("peerIp=%s", this->mSdpTrack.peerIp);
            LOGI("peerRtpPort=%d", this->mSdpTrack.peerRtpPort);
            LOGI("ssrc_s=%s", this->mSdpTrack.ssrc_s);
            LOGI("ssrc=%d", this->mSdpTrack.ssrc);
            LOGI("peerRtpTransProtocol=%s", this->mSdpTrack.peerRtpTransProtocol);
            printf("\r\n");
            printf("-----------my parse end-----------\n");

            // LOGI("trackSize=%d", trackSize);

            // 还有一点需要注意，这个设置：a=sendonly
            char sdpBuf[2048];
            snprintf(
                sdpBuf, sizeof(sdpBuf),
                "v=0\r\n"
                "o=%s %d 1 IN IP4 %s\r\n"
                "s=Play\r\n"
                "c=IN IP4 %s\r\n"
                "t=0 0\r\n"
                "m=video %d %s 96\r\n"
                "a=sendonly\r\n"
                "a=rtpmap:96 PS/90000\r\n"
                "y=%s\r\n" // 必须与INVITE中的y值一致
                "f=v/2/4///a///\r\n",
                // "a=rtpmap:98 H264/90000\r\n"
                // "a=rtpmap:97 MPEG4/90000\r\n",
                mClientConfig->id,
                genRandomInt(),
                mClientConfig->ip,
                mClientConfig->ip,
                mClientConfig->localRtpPort,
                this->mSdpTrack.peerRtpTransProtocol,
                this->mSdpTrack.ssrc_s
                );

            osip_message_set_body(answer, sdpBuf, strlen(sdpBuf));
            osip_message_set_content_type(answer, "application/sdp");
            eXosip_call_send_answer(mSipCtx, evtp->tid, 200, answer);
        }
        eXosip_unlock(mSipCtx);

        return 0;
    }

    int SipClient::response_ack(eXosip_event_t *evtp)
    {
        char *username = evtp->request->to->url->username; // 对应摄像头的DeviceID
        char *CallID = evtp->request->call_id->number;
        LOGI("接收到信令服务的ACK，开始ps over rtp 推流");
        printf("username:%s\n", username);
        printf("CallID:%s\n", CallID);
        // 正式开始推流
        curl_start_rtp(this->mSdpTrack,this->mClientConfig);
        return 0;
    }

    int SipClient::response_bye(eXosip_event_t *evtp)
    {
        char *username = evtp->request->to->url->username; // 对应摄像头的DeviceID
        char *CallID = evtp->request->call_id->number;
        LOGI("接收到信令服务的BYE，停止ps over rtp 推流");
        LOGI("username:%s", username);
        LOGI("CallID:%s", CallID);
        // 停止推流
        curl_stop_rtp();

        return 0;
    }
    int SipClient::sip_event_handle(eXosip_event_t *evtp)
    {
        switch (evtp->type)
        {
        case EXOSIP_MESSAGE_NEW:
            // LOGI("EXOSIP_MESSAGE_NEW");

            if (MSG_IS_REGISTER(evtp->request))
            {
                LOGI("MSG_IS_REGISTER，不应该出现的响应，请排查问题");
            }
            else if (MSG_IS_MESSAGE(evtp->request))
            {
                this->response_message(evtp);
            }
            else
            {
                LOGI("未定义类型的MESSAGE");

                this->dump_request(evtp);

                /*
                // 可能会出现的请求
                BYE sip:00662800000403000001@192.168.8.200:5060 SIP/2.0
                Via: SIP/2.0/UDP 192.168.8.114:5060;branch=z9hG4bK695c5ff8b5c014866ffc6a554c242a6d
                From: <sip:00662800000401000001@0066280000>;tag=185326220
                To: <sip:00662802002006028104@0066280000>;tag=2009556327
                Call-ID: 05a7fc88c30878338ff311a788e9cefa@192.168.8.114
                CSeq: 185 BYE
                Max-forwards: 70
                Content-Length: 0
                */
            }
            break;
        case EXOSIP_CALL_ANSWERED:
            LOGI("EXOSIP_CALL_ANSWERED type=%d:这里应该主动发送ACK之后的回复", evtp->type);
            // this->dump_request(evtp);
            // this->dump_response(evtp);
            break;
        case EXOSIP_REGISTRATION_FAILURE:
            LOGI("EXOSIP_REGISTRATION_FAILURE type=%d", evtp->type);
            LOGI("mRegistered=%d,mRegisterId=%d", mRegistered, mRegisterId);
            this->mRegistered = false;
            if (evtp->response && evtp->response->status_code == 401 && this->mRegistered == false)
            {
                osip_www_authenticate_t *auth;
                osip_message_get_www_authenticate(evtp->response, 0, &auth);

                // 提取认证参数
                const char *realm = auth->realm;
                const char *nonce = auth->nonce;

                // LOGI("realm=%s",realm);
                // LOGI("nonce=%s",nonce);
                // 生成 Authorization 头
                char auth_header[512];
                build_authorization_header(
                    mClientConfig->id,
                    mServerConfig->getSipPass(),
                    "REGISTER",
                    realm,
                    nonce,
                    "34020000002000000001@10.164.220.149:5060", // 根据实际 URI 修改
                    auth_header,
                    sizeof(auth_header));
                // LOGI("auth_header=%s", auth_header);

                if (eXosip_add_authentication_info(mSipCtx, mClientConfig->id, mClientConfig->id, mServerConfig->getSipPass(), auth_header, NULL) < 0)
                {
                    LOGI("eXosip_add_authentication_info error");
                }
                osip_message_t *msg;
                eXosip_register_build_register(mSipCtx, mRegisterId, mServerConfig->getSipExpiry(), &msg);
                eXosip_register_send_register(mSipCtx, mRegisterId, msg);
            }
            break;
        case EXOSIP_REGISTRATION_SUCCESS:
            LOGI("EXOSIP_REGISTRATION_SUCCESS type=%d", evtp->type);
            this->mRegistered = true;
            // LOGI("mRegistered=%d,mRegisterId=%d", mRegistered, mRegisterId);

            //                this->dump_request(evtp);
            //                this->request_message_keepalive();
            break;
        case EXOSIP_CALL_INVITE:
            LOGI("EXOSIP_CALL_INVITE type=%d: 接收到对方发送了Invite请求", evtp->type);
            //                this->dump_request(evtp);
            //                this->dump_response(evtp);
            this->response_invite(evtp);
            break;
        case EXOSIP_CALL_ACK:
            LOGI("EXOSIP_CALL_ACK type=%d: 收到来自对方ACK请求。准备国标推流。", evtp->type);
            // dump_request(evtp);
            this->response_ack(evtp);
            break;
        case EXOSIP_IN_SUBSCRIPTION_NEW:
            LOGI("EXOSIP_IN_SUBSCRIPTION_NEW type=%d", evtp->type);
            // dump_request(evtp);
            break;
        case EXOSIP_CALL_NOANSWER:
        {
            LOGI("EXOSIP_IN_SUBSCRIPTION_NEW type=%d", evtp->type);
            break;
        }
        case EXOSIP_CALL_MESSAGE_NEW: // 14
        {
            LOGI("EXOSIP_CALL_MESSAGE_NEW type=%d", evtp->type);
            this->dump_request(evtp);
            this->dump_response(evtp);
            break;
        }
        case EXOSIP_CALL_CLOSED: // 21
        {
            LOGI("EXOSIP_CALL_CLOSED type=%d", evtp->type);
            this->dump_request(evtp);
            this->dump_response(evtp);
            this->response_bye(evtp);
            break;
        }
        case EXOSIP_CALL_RELEASED: // 22
        {
            LOGI("EXOSIP_CALL_RELEASED type=%d: Bye确认", evtp->type);
            break;
        }
        case EXOSIP_MESSAGE_REQUESTFAILURE:
            LOGI("EXOSIP_MESSAGE_REQUESTFAILURE type=%d", evtp->type);
            LOGI("evtp->textinfo= '%s' ", evtp->textinfo);
            if (evtp->ack)
            {
                char *ack_str;
                size_t ack_str_len;
                osip_message_to_str(evtp->ack, &ack_str, &ack_str_len);
                LOGI("ack_str=%s", ack_str);
            }
            this->dump_request(evtp);
            this->dump_response(evtp);

            break;
        case EXOSIP_MESSAGE_ANSWERED:
            LOGI("EXOSIP_MESSAGE_ANSWERED type=%d: 接收到来自对应的MESSAGE请求。", evtp->type);
            break;
        default:
            LOGI("type=%d unknown ", evtp->type);
            break;
        }

        return 0;
    }

    int SipClient::parse_xml(const char *data, const char *s_mark, bool with_s_make, const char *e_mark, bool with_e_make, char *dest)
    {
        const char *satrt = strstr(data, s_mark);

        if (satrt != NULL)
        {
            const char *end = strstr(satrt, e_mark);
            if (end != NULL)
            {
                int s_pos = with_s_make ? 0 : strlen(s_mark);
                int e_pos = with_e_make ? strlen(e_mark) : 0;

                strncpy(dest, satrt + s_pos, (end + e_pos) - (satrt + s_pos));
            }
            return 0;
        }
        return -1;
    }
    void SipClient::dump_request(eXosip_event_t *evt)
    {
        char *s;
        size_t len;
        osip_message_to_str(evt->request, &s, &len);
        LOGI("\n打印请求包开始\ntype=%d\n%s\n打印请求包结束\n", evt->type, s);
    }
    void SipClient::dump_response(eXosip_event_t *evt)
    {
        char *s;
        size_t len;
        osip_message_to_str(evt->response, &s, &len);
        LOGI("\n打印响应包开始\ntype=%d\n%s\n打印响应包结束\n", evt->type, s);
    }
}