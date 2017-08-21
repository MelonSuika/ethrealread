#include "kdvtype.h"
#include "osp.h"
#include "EthFileRead.h"


/*文件格式24(file head)+8(pack head)+4(pack len)+4(pack len)+14(ethernet header)
+ 20(ip header) + 12(offset) + 1(tcp head len) + data 

*/

/*
补：
24(pcap header)
 + 16(packet header) = (4(timestamp高位)+ 4(timestamp低位)+ 4(caplen，当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置)+ 4(len))

*/


/* 头格式

#pragma pack(push)
#pragma pack(1)
struct pcap_file_header
{
	DWORD           magic;
	WORD            version_major;
	WORD            version_minor;
	DWORD           thiszone;
	DWORD           sigfigs;
	DWORD           snaplen;
	DWORD           linktype;
};
#pragma pack(pop);
*/

const u8 ETHREAL_FILE_HEADER[24]={0xd4,0xc3,0xb2,0xa1,
                                  0x02,0x00,0x04,0x00,
                                  0x00,0x00,0x00,0x00,
                                  0x00,0x00,0x00,0x00, 
							      0x00,0x00,0x00,0x00,
                                  0x00,0x00,0x00,0x00};

#define MAX_PACKET_SIZE 2048

CEthFile::CEthFile()
{
    m_pFile   = NULL;
    m_dwSrcIp = 0;
    m_dwDstIp = 0;
    m_pbyBuff = NULL;

    memset(&m_frame_hdr, 0, sizeof(m_frame_hdr));
}


CEthFile::~CEthFile()
{
    Close();
}


void CEthFile::Close()
{
    if (NULL != m_pFile)
    {
        fclose(m_pFile);
        m_pFile = NULL;
    }

    if (NULL != m_pbyBuff)
    {
        delete m_pbyBuff;
    }
}


BOOL32 CEthFile::Create(s8* pszFileName)
{
    Close();
    
    if (NULL == pszFileName)
    {
        return FALSE;
    }
    
    m_pFile = fopen(pszFileName, "rb");
    if (NULL == m_pFile)
    {
        printf("file open error!\n");
        return FALSE;
    }
    
    do
    {   
        u8 abyHeader[sizeof(ETHREAL_FILE_HEADER)];
        s32 nLen;
        nLen = fread(&abyHeader, 1, sizeof(ETHREAL_FILE_HEADER), m_pFile);
        if (nLen < sizeof(ETHREAL_FILE_HEADER))
        {
            printf("file length is error!\n");
            break;
        }
        
//         if(memcmp(abyHeader, ETHREAL_FILE_HEADER, 16))
//         {
//             printf("file format is error!\n");
//             break;
//         }

		// 仅支持 Ethernet
		/*以下是数据值与链路层类型的对应表
		0            BSD       loopback devices, except for later OpenBSD
		1            Ethernet, and Linux loopback devices   以太网类型，大多数的数据包为这种类型。
		6            802.5 Token Ring
		7            ARCnet
		8            SLIP
		9            PPP
		10          FDDI
		100        LLC/SNAP-encapsulated ATM
		101        raw IP, with no link
		102        BSD/OS SLIP
		103        BSD/OS PPP
		104        Cisco HDLC
		105        802.11
		108        later OpenBSD loopback devices (with the AF_value in network byte order)
		113               special Linux cooked capture
		114               LocalTalk
		*/
		u32 dwNetworkType = *((u32*)(abyHeader+20));
		if (dwNetworkType != 1)
		{	
            printf("file format is error, not ethernet!\n");
            break;
		}

        m_pbyBuff = new u8[MAX_PACKET_SIZE];
        if (NULL == m_pbyBuff)
        {
            printf("Buff Create Failed!\n");
            break;
        }

        return TRUE;
        
    } while(0);
    
    Close();
    return FALSE;
    
}

BOOL32 CEthFile::SetFilter(u32 dwSrcIp, u32 dwDstIp, u16 wSrcPort, u16 wDstPort)
{
    m_dwSrcIp = dwSrcIp;
    m_dwDstIp = dwDstIp;
    m_wSrcPort = wSrcPort;
    m_wDstPort = wDstPort;
    return TRUE;
}

u8* CEthFile::GetData()
{
    if (GetLen() > 0)
    {
        return m_pbyBuff;
    }
    else
        return NULL;
}


s32 CEthFile::GetLen()
{
    return m_nDataLen;    
}

s32 CEthFile::FirstPacket()
{
    fseek(m_pFile, sizeof(ETHREAL_FILE_HEADER), SEEK_SET);
    memset(&m_frame_hdr, 0, sizeof(m_frame_hdr));    
    return NextPacket();
}

u16 CEthFile::GetUdpDstPort()
{
    return m_e_udphdr.uh_dport;
}

frame_hdr* CEthFile::GetFrame()
{
    if (GetLen() > 0)
    {
        return &m_frame_hdr;
    }
    else
        return NULL;
}


//返回UDP长度
s32 CEthFile::NextPacket()
{
    s32 nLen;

  
    BOOL32 bOK = FALSE;

    m_frame_hdr.pack_len = 0;
    
    u32 dwOffsetInFrame = 0;

    s32 nFrameCount = 0;

    do
    {
        
        if (m_frame_hdr.pack_len - dwOffsetInFrame > 0 )
        {
            if (0 != fseek(m_pFile, m_frame_hdr.pack_len - dwOffsetInFrame, SEEK_CUR))
            {
                break;
            }
        }
       
        //读帧头
        nLen = fread(&m_frame_hdr,  1, sizeof(frame_hdr), m_pFile);
        if (nLen < sizeof(frame_hdr))
        {
            break;
        }
        
        nFrameCount++;
        
        if (m_frame_hdr.pack_len == 0 || m_frame_hdr.pack_len < m_frame_hdr.cap_len)
        {
            printf("Frame header error\n");
        }
        dwOffsetInFrame = 0;     
        
        //读以太网头
        nLen = fread(&m_eth_hdr, 1, sizeof(eth_hdr), m_pFile);
        if (nLen < sizeof(eth_hdr))
        {
            break;
        }
        dwOffsetInFrame += nLen; 
        m_eth_hdr.st_ntoh();

        if (m_eth_hdr.type != 0x0800) // 网际协议（IP）
        {
            if (m_eth_hdr.type == 0x8864) // 以太网上的 PPP（PPP 会话阶段） （PPPoE，PPP Over Ethernet<PPP Session Stage>）
            {
                nLen = fread(&m_e_PPPoE, 1, sizeof(m_e_PPPoE), m_pFile);
                if (sizeof(m_e_PPPoE) != nLen)
                {
                    printf("read PPPoE header error!\n");
                    break;
                }
                dwOffsetInFrame += nLen;

                nLen = fread(&m_e_P2P, 1, sizeof(m_e_P2P), m_pFile);
                if(sizeof(m_e_P2P) != nLen)
                {
                    printf("read P2P header error!\n");
                    break;
                }
                dwOffsetInFrame += nLen;
                
            }
            else
            {
                continue;
            }
                       
        }
        
        //读IP包头
        nLen = fread(&m_e_ip, 1, sizeof(e_ip), m_pFile);
        if (nLen < sizeof(e_ip))
        {
            break;
        }
        dwOffsetInFrame += nLen; 
        m_e_ip.st_ntoh();

        if (m_e_ip.ip_v_hl != 0x45)
        {
            continue;
        }

        //UDP协议
        if (m_e_ip.ip_p != 0x11)
        {
            continue;
        }
    
        //不进行比较源地址
        if (m_dwSrcIp != 0 &&  m_e_ip.ip_src != m_dwSrcIp)
        {
            continue;
        }

        
        //比较目标地址
        if (m_dwDstIp != 0 &&  m_e_ip.ip_dst != m_dwDstIp)
        {
            continue;
        }

        
        //IP分片
        if (m_e_ip.ip_off != 0 && m_e_ip.ip_off!= 0x4000)
        {
            printf("IP fragment!\n");
            continue;
        }
        
        //读UDP头
        nLen = fread(&m_e_udphdr, 1, sizeof(e_udphdr), m_pFile);
        if (nLen < sizeof(e_udphdr))
        {
            break;
        }
        dwOffsetInFrame += nLen; 
        m_e_udphdr.st_ntoh();
        
        if (m_wSrcPort != 0 && m_wSrcPort != m_e_udphdr.uh_sport)
        {
            continue;
        }

        if (m_wDstPort != 0 && m_wDstPort != m_e_udphdr.uh_dport)
        {
            continue;
        }


        s32 nUdpDataLen;
        nUdpDataLen = m_e_udphdr.uh_ulen - sizeof(e_udphdr);

        //not equal because of capture cut lost data
        if (m_frame_hdr.cap_len - dwOffsetInFrame < (u32)nUdpDataLen)
        {
            printf("Frame fragile: should: %d!, real: %d\n", nUdpDataLen, m_frame_hdr.cap_len - dwOffsetInFrame);
            //continue;
        }

        nLen = fread(m_pbyBuff, 1, m_frame_hdr.cap_len - dwOffsetInFrame, m_pFile);
        if (nLen < (s32)m_frame_hdr.cap_len - dwOffsetInFrame)
        {
            printf("read udp data error!\n");
            break;
        }
        dwOffsetInFrame += nLen;
        if (m_frame_hdr.cap_len - dwOffsetInFrame > 0)
        {
            fseek(m_pFile, m_frame_hdr.cap_len - dwOffsetInFrame, SEEK_CUR);
        }
        
        
        bOK = TRUE;
    } while(!bOK);

    if (!bOK)
    {
        m_nDataLen = -1;
    }
    else
    {
        m_nDataLen = nLen;
    }
    

    return m_nDataLen;
}


