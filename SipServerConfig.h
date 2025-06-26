//
// Created by bxc on 2022/12/13.
//

#ifndef BXC_GB28181CLIENT_SIPSERVERCONFIG_H
#define BXC_GB28181CLIENT_SIPSERVERCONFIG_H
namespace BXC {
    struct SipServerConfig {
    public:
        SipServerConfig(
            const char* ip, int port, const char* sipId, const char* sipRealm, const char* sipPass, int sipTimeout,
            int sipExpiry)
            : mIp(ip)
            , mPort(port)
            , mSipId(sipId)
            , mSipRealm(sipRealm)
            , mSipPass(sipPass)
            , mSipTimeout(sipTimeout)
            , mSipExpiry(sipExpiry) {}
        SipServerConfig() = delete;
        ~SipServerConfig() = default;

    public:
        const char* getIp() const { return mIp; }
        int getPort() const { return mPort; }
        const char* getSipId() const { return mSipId; }
        const char* getSipRealm() const { return mSipRealm; }
        const char* getSipPass() const { return mSipPass; }
        int getSipTimeout() const { return mSipTimeout; }
        int getSipExpiry() const { return mSipExpiry; }

    private:
        const char* mIp; // SIP服务IP
        int mPort; // SIP服务端口
        const char* mSipId; // SIP服务器ID
        const char* mSipRealm; // SIP服务器域
        const char* mSipPass; // SIP password
        int mSipTimeout; // SIP超时
        int mSipExpiry; // SIP到期
    };


}
#endif // BXC_GB28181CLIENT_SIPSERVERCONFIG_H
