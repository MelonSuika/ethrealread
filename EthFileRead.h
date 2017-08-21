#ifndef _ETHFILEREAD_H_
#define _ETHFILEREAD_H_


typedef struct 
{
    u32 time_hi;
    u32 time_lo;
    u32 cap_len;
    u32 pack_len;

} frame_hdr;


typedef struct _mac_addr
{
    u8 addr[6];
} mac_addr;

typedef struct _eth_hdr {
    mac_addr dst;
    mac_addr src;
    u16     type;
    
    void st_hton()
    {
        type  = htons(type);
    };
    
    void st_ntoh()
    {
        type  = ntohs(type);
    };
} eth_hdr;

typedef struct _e_PPPoE
{
    u8  ver_type;
    u8  code;
    u16 sessionID;
    u16 payloadLength;

    void st_hton()
    {
        sessionID = htons(sessionID);
        payloadLength = htons(payloadLength);
    }

    void st_ntoh()
    {
        sessionID = ntohs(sessionID);
        payloadLength = ntohs(payloadLength);
    }
}e_PPPoE;

typedef struct _e_P2P
{
    u16 protocol;

    void st_hton()
    {
        protocol = htons(protocol);
    }
    void st_ntoh()
    {
        protocol = ntohs(protocol);
    }
}e_P2P;


#define ip_addr u32

typedef struct _e_ip
{
    u8      ip_v_hl; /* combines ip_v and ip_hl */
    u8      ip_tos;
    u16     ip_len;
    u16     ip_id;
    u16     ip_off;
    u8      ip_ttl;
    u8      ip_p;
    u16     ip_sum;
    ip_addr ip_src;
    ip_addr ip_dst;
    
    void st_hton()
    {
        ip_len  =  htons(ip_len);
        ip_id   =  htons(ip_id);
        ip_off  =  htons(ip_off);
        ip_sum  =  htons(ip_sum);
        
    };
    
    void st_ntoh()
    {
        ip_len  = ntohs(ip_len);
        ip_sum  = ntohs(ip_sum);
        ip_off  = ntohs(ip_off);
        ip_sum  = ntohs(ip_sum);
    };
    
} e_ip;


/* UDP structs and definitions */
typedef struct _e_udphdr
{
    u16     uh_sport;
    u16     uh_dport;
    u16     uh_ulen;
    u16     uh_sum;
    
    void st_hton()
    {
        uh_sport  =  htons(uh_sport);
        uh_dport  =  htons(uh_dport);
        uh_ulen   =  htons(uh_ulen);
        uh_sum    =  htons(uh_sum);
    };
    
    void st_ntoh()
    {
        uh_sport  = ntohs(uh_sport);
        uh_dport  = ntohs(uh_dport);
        uh_ulen   = ntohs(uh_ulen);
        uh_sum    = ntohs(uh_sum);
    };
} e_udphdr;

class CEthFile
{
public:
    CEthFile();
    ~CEthFile();

    BOOL32 Create(s8* pszFileName);
    
    void Close();           // 资源释放函数

    s32 NextPacket();

    s32 FirstPacket();

    u16 GetUdpDstPort();

    u8* GetData();
    s32 GetLen();

    frame_hdr* GetFrame();
    
    BOOL32 SetFilter(u32 dwSrcIp, u32 dwDstIp, u16 wSrcPort, u16 wDstPort);
	void   SetParam(BOOL32 bRepeat, BOOL32 bWriteFile)
	{
		m_bRepeat = bRepeat;
		m_bWriteFile = bWriteFile;
	}
    
private:
    FILE* m_pFile;
    u8* m_pbyBuff;

    frame_hdr m_frame_hdr;
    eth_hdr   m_eth_hdr;
    e_PPPoE   m_e_PPPoE;
    e_P2P     m_e_P2P;
    e_ip      m_e_ip;
    e_udphdr  m_e_udphdr;
    
    u32       m_dwSrcIp;
    u32       m_dwDstIp;
    u16       m_wSrcPort;
    u16       m_wDstPort;
    s32       m_nDataLen;
public:
	BOOL32    m_bRepeat;
	BOOL32    m_bWriteFile;
};






#endif // _ETHFILEREAD_H_