//
// Created by bxc on 2022/12/13.
//

#ifndef BXC_GB28181CLIENT_SIPCLIENT_H
#define BXC_GB28181CLIENT_SIPCLIENT_H
#include <osip2/osip_mt.h>
#include <eXosip2/eXosip.h>
#include <vector>
#include <mutex>
#include <queue>

struct HttpResponse
{
    char *HttpResponse;
    size_t size;
};

namespace BXC
{
    // 用于存储响应数据的结构体
    struct SdpTrack
    {
        char mediaType[10]{0};         // video
        char peerStreamType[40] = {0}; // 96 98 97
        char peerIp[40] = {0};         // 接收国标推流Player的IP地址
        int peerRtpPort = 0;           // 15060
        char peerRtpTransProtocol[20]{0};  // 对端通过sdp发送过来的需要的rtp传输方式：TCP/RTP/AVP or RTP/AVP
        int ssrc = 0;
        char ssrc_s[20];
    };

    struct SipServerConfig;
    struct SipClientConfig
    {
    public:
        SipClientConfig(const char *ua, const char *ip, int port, const char *id, int localRtpPort)
        {
            this->ua = ua;
            this->ip = ip;
            this->port = port;
            this->id = id;
            this->localRtpPort = localRtpPort;
            this->quit = false;
        }
        SipClientConfig() = delete;

    public:
        const char *ua;
        const char *ip;
        int port;
        const char *id;
        int localRtpPort;
        bool quit;
    };
    class SipClient
    {
    public:
        explicit SipClient(SipServerConfig *serverConfig, SipClientConfig *clientConfig);
        SipClient() = delete;
        ~SipClient();

    public:
        void loop();

    private:
        SipServerConfig *mServerConfig;
        SipClientConfig *mClientConfig;

        struct eXosip_t *mSipCtx;
        struct SdpTrack mSdpTrack;
        bool mRegistered;
        int mRegisterId;

    private:
        int init_sip_client();
        int sip_event_handle(eXosip_event_t *evtp);
        int response_message_answer(eXosip_event_t *evtp, int code);
        int response_message(eXosip_event_t *evtp);
        int response_invite(eXosip_event_t *evtp);
        int response_ack(eXosip_event_t *evtp);
        int response_bye(eXosip_event_t *evtp);
        int request_register();

        int request_message_keepalive();
        int request_message_catalog(int);
        int request_message_DeviceStatus(int);
        int request_message_DeviceInfo(int);

        int parse_xml(const char *data, const char *s_mark, bool with_s_make, const char *e_mark, bool with_e_make, char *dest);
        void dump_request(eXosip_event_t *evt);
        void dump_response(eXosip_event_t *evt);
    };

}
#endif // BXC_GB28181CLIENT_SIPCLIENT_H
