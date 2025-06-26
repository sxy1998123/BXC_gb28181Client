//
// Created by bxc on 2022/12/15.
//

#ifndef BXC_GB28181CLIENT_RTPSENDPS_H
#define BXC_GB28181CLIENT_RTPSENDPS_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#ifndef WIN32 // Linux系统
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#endif // !WIN32

#include <thread>
/***
*@remark:  讲传入的数据按位一个一个的压入数据
*@param :  buffer   [in]  压入数据的buffer
*          count    [in]  需要压入数据占的位数
*          bits     [in]  压入的数值
*/
#define bits_write(buffer, count, bits)\
{\
	bits_buffer_s *p_buffer = (buffer); \
	int i_count = (count); \
	uint64_t i_bits = (bits); \
while (i_count > 0)\
{\
	i_count--; \
if ((i_bits >> i_count) & 0x01)\
{\
	p_buffer->p_data[p_buffer->i_data] |= p_buffer->i_mask; \
}\
	else\
{\
	p_buffer->p_data[p_buffer->i_data] &= ~p_buffer->i_mask; \
}\
	p_buffer->i_mask >>= 1;         /*操作完一个字节第一位后，操作第二位*/\
if (p_buffer->i_mask == 0)     /*循环完一个字节的8位后，重新开始下一位*/\
{\
	p_buffer->i_data++; \
	p_buffer->i_mask = 0x80; \
}\
}\
}

namespace BXC {

    #define PS_HDR_LEN  14 // ps header 字节长度
    #define SYS_HDR_LEN 18 // ps system header 字节长度
    #define PSM_HDR_LEN 24 // ps system map    字节长度
    #define PES_HDR_LEN 19 // ps pes header    字节长度
    #define RTP_HDR_LEN 12 // rtp header       字节长度
    #define RTP_VERSION 2  // rtp 版本号
    #define RTP_MAX_PACKET_BUFF 1460 // rtp传输时的最大包长
    #define PS_PES_PAYLOAD_SIZE 65522 // 分片进循发送的最大长度上限

    union LESize
    {
        unsigned short int  length;
        unsigned char   byte[2];
    };

    struct bits_buffer_s {
        unsigned char* p_data;
        unsigned char  i_mask;
        int i_size;
        int i_data;
    };

    struct Data_Info_s {
        uint64_t s64CurPts;
        int      IFrame;
        uint16_t u16CSeq;
        uint32_t u32Ssrc;
        char szBuff[RTP_MAX_PACKET_BUFF];
    };



    class RtpSendPs{
    public:
        explicit RtpSendPs(const char* rtpServerIp,int rtpServerPort,int localRtpPort);
        RtpSendPs() = delete;
        ~RtpSendPs();
    public:
        void start();
        void stop();
    private:
        int findStartCode(unsigned char* buf, int zeros_in_startcode);
        int getNextNalu(FILE* inpf, unsigned char* buf);

        int gb28181_streampackageForH264(char* pData, int nFrameLen, Data_Info_s* pPacker, int stream_type);
        int gb28181_make_ps_header(char* pData, unsigned long long s64Scr);
        int gb28181_make_sys_header(char* pData);
        int gb28181_make_psm_header(char* pData);
        int gb28181_make_pes_header(char* pData, int stream_id, int payload_len, unsigned long long pts, unsigned long long dts);
        int gb28181_send_rtp_pack(char* databuff, int nDataLen, int mark_flag, Data_Info_s* pPacker);
        int gb28181_make_rtp_header(char* pData, int marker_flag, unsigned short cseq, long long curpts, unsigned int ssrc);
        int SendDataBuff(char* buff, int size);

        static void SendDataThread(void *arg);
    private:
        int mSockFd = -1;
        const char * mRtpServerIp;
        int          mRtpServerPort = 0;
        int          mLocalRtpPort = 0;

        std::thread * mThread = nullptr;
        bool mQuit;
    };


}
#endif //BXC_GB28181CLIENT_RTPSENDPS_H