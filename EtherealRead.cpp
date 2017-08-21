#include "kdvtype.h"
#include "osp.h"
#include "EthFileRead.h"
#include "kdvsys.h"

/*******************************

*******************************/
s32 SendProc(CEthFile* pcEthFile, u32 dwSndDstIp, u16 wSndDstPort, u32 dwSndSrcIp, u16 wSndSrcPort)
{
	FILE *fpRawData = NULL;
	FILE *fpRawDataLen = NULL;

    if (NULL == pcEthFile)
    {
        return -1;
    }

#if 0   //不另存文件
	if (pcEthFile->m_bWriteFile)
	{
		fpRawData = fopen("c:\\data.dat", "wb");
		fpRawDataLen = fopen("c:\\datalen.txt", "wb");
	}
#endif
    
    s32 nSocket;
    nSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    printf("socket = %d\n", nSocket);
    if (nSocket < 0)
    {
        return -1;
    }

    /* 绑定指定端口发送数据 */
    if (wSndSrcPort != 0)
    {
        s32 nResult = 0;
        struct sockaddr_in sout;
        memset(&sout, 0, sizeof(sout));

        sout.sin_family      = AF_INET;
        sout.sin_port        = htons(wSndSrcPort);
        sout.sin_addr.s_addr = 0;
        nResult = bind(nSocket, (struct sockaddr*)&sout, sizeof(sout));
        if (nResult != 0)
        {
            printf("warning: bind to specified port %d error!", wSndSrcPort);
            Sleep(5000);
        }
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(wSndDstPort);
    sin.sin_addr.s_addr = dwSndDstIp;

    
    s32 nLen;
    s32 nCount = 0;
    u32 dwSpan = 0;
    u32 dwNowHi;
    u32 dwNowLo;
    frame_hdr* ptFrame;
    

StartRead:
    nLen = pcEthFile->FirstPacket();
    ptFrame = pcEthFile->GetFrame();

    if (nLen > 0 && NULL != ptFrame)
    {
        dwNowHi = ptFrame->time_hi;
        dwNowLo = ptFrame->time_lo;        
    }    
    
    u64 qwLocalStartTime;
    u32 dwRunTime = 0;
    qwLocalStartTime = GetTickCount();
    qwLocalStartTime *= 1000;

    while(nLen > 0)
    {   
        nCount++;
        printf("packet %d len: %d ", nCount, nLen);
        
        if (dwSpan != 0)
        {
            printf("time span %d\n", dwSpan);
        }
        else
        {
            printf("\n");
        }
        
        u8* pData;
        
        pData = pcEthFile->GetData();
        if (nLen > 0 && NULL != pData)
        {
            if (wSndDstPort == 0)
            {
                u16 wRealPort = pcEthFile->GetUdpDstPort();
                sin.sin_port = htons(wRealPort);
            }

            sendto(nSocket, (s8*)pData, nLen, 0, (struct sockaddr*)&sin, sizeof(sin));

			if (pcEthFile->m_bWriteFile && fpRawData && fpRawDataLen)
			{
				fwrite(pData, nLen, 1, fpRawData);

				s8 abyTmp[16];
				sprintf(abyTmp, "%d\r\n", nLen);
				fwrite(abyTmp, 1, strlen(abyTmp), fpRawDataLen);
			}
            
        }
        
        u32 dwLastHi = 0;
        u32 dwLastLo = 0;
        
        dwLastHi = dwNowHi;
        dwLastLo = dwNowLo;
        
        nLen = pcEthFile->NextPacket();
        if (nLen > 0)
        {
            ptFrame = pcEthFile->GetFrame();
            
            dwNowHi = ptFrame->time_hi;
            dwNowLo = ptFrame->time_lo;
            
			if ((dwLastHi == dwNowHi && dwLastLo > dwNowLo) || dwLastHi == dwNowHi+1)
            { // at duro cpu, sometime, time is a little revert
                dwLastHi = dwNowHi;
                dwLastLo = dwNowLo;
			}

            if (dwLastHi > dwNowHi)
            {
                dwLastHi = dwNowHi;
                dwLastLo = dwNowLo;
            }
            
            dwSpan = (dwNowHi-dwLastHi)*1000000;

            if (dwNowLo >= dwLastLo)
            {
                dwSpan = dwSpan + (dwNowLo - dwLastLo);
            }
            else
            {
                dwSpan = dwSpan - (dwLastLo - dwNowLo);
            }
             
            dwSpan = 20 * 1000;
            dwRunTime += dwSpan;
            
            u64 qwNowTime = GetTickCount();
            qwNowTime *= 1000;
            u64 qwPlayTick = qwLocalStartTime + dwRunTime;
            
            //当前时间相差大于1S（因为中间程序暂停缘故），则不进行弥补，直接跳过。
            if (qwPlayTick + 1000*1000 < qwNowTime)
            {
                dwRunTime = qwNowTime - qwLocalStartTime;
            }
            else if (qwPlayTick > qwNowTime)
            {
                u32 dwSleepTime = dwRunTime + qwLocalStartTime - qwNowTime;
                if (dwSleepTime > 200*1000)
                {
                    s32 i = 0;
                }
                Sleep(dwSleepTime/1000);
            }
        }
    }

	if (pcEthFile->m_bRepeat)
		goto StartRead;

	if (fpRawData)
	{
		fclose(fpRawData);
	}

	if (fpRawDataLen)
	{
		fclose(fpRawDataLen);
	}

    closesocket(nSocket);
    return nCount;

}

s32 main(int argc, char *argv[])
{

#ifdef WIN32
    {
        WSADATA wsadata;
        if(WSAStartup(0x0101, &wsadata)!=0)
            return FALSE;
    }
#endif

    s8* strFileDefault = "config.ini"; /* config file name */

    
    s8* strFileConfig = strFileDefault;
    // ?strFileName的作用是什么
    s8* strFilename = NULL;

    if (2 >= argc)
    {
        printf("you can use: %s <config> <filename>\n", argv[0]);
        Sleep(2 * 1000);
    }
    else
    {
        strFileConfig = argv[1];
        //strFilename = argv[2];
    }

    s8 achFilename[256] = "test";

    /* receive */
    s8  achRcvSrcIp[64];
    s8  achRcvDstIp[64];
    s32 nSrcPort;
    s32 nDstPort;

    /* send */
    s8  achSendDstIp[64];
    s8  achSendSrcIp[64];
    s32 nSendDstPort;
    s32 nSendSrcPort;

    /* ctrl variables */
	BOOL32 bRepeat;
	BOOL32 bWriteYUVFile;
    BOOL32 bOK = FALSE;

    do
    {
        if (!GetRegKeyString(strFileConfig,
            "FILTERINFO", 
            "SRC_IP", 
            "0.0.0.0",
            achRcvSrcIp,
            sizeof(achRcvSrcIp)))
        {
            printf("Read Filter SRC_IP error!\n");
			strcpy(achRcvSrcIp, "0.0.0.0");
        }
        
        if (!GetRegKeyInt(strFileConfig,
            "FILTERINFO", 
            "SRC_PORT", 
            0,
            &nSrcPort))
        {
            printf("Read Filter SRC_PORT error!\n");
			nSrcPort = 0;
        }
        
        if (!GetRegKeyString(strFileConfig,
            "FILTERINFO", 
            "DST_IP", 
            "0.0.0.0",
            achRcvDstIp,
            sizeof(achRcvDstIp)))
        {
            printf("Read Filter DST_IP error!\n");
            strcpy(achRcvDstIp, "0.0.0.0");
        }
        
        if (!GetRegKeyInt(strFileConfig,
            "FILTERINFO", 
            "DST_PORT", 
            0,
            &nDstPort))
        {
            printf("Read Filter DST_PORT error!\n");
            nDstPort = 0;
        }

		GetRegKeyString(strFileConfig, "FILTERINFO", "FILENAME", "test", 	achFilename, 255);	

        if (!GetRegKeyString(strFileConfig,
            "SENDINFO", 
            "DST_IP", 
            "127.0.0.1",
            achSendDstIp,
            sizeof(achSendDstIp)))
        {
            printf("Read Send DST_IP error!\n");
            break;
        }
 
        /* obtain send destination port */
        if (!GetRegKeyInt(strFileConfig,
            "SENDINFO", 
            "DST_PORT", 
            0,
            &nSendDstPort))
        {
            printf("Read Send DST_PORT error!\n");
            break;
        } 

        /* obtain local send addr */
        if (!GetRegKeyString(strFileConfig,
            "SENDINFO",
            "SRC_IP",
            "127.0.0.1",
            achSendSrcIp,
            sizeof(achSendSrcIp)))
        {
            printf("use default local send addr %s\n", achSendSrcIp);
        }

        /* obtain local send port */
        if (!GetRegKeyInt(strFileConfig,
            "SENDINFO",
            "SRC_PORT",
            0,
            &nSendSrcPort))
        {
            printf("use default local send port %d\n", nSendSrcPort);
        }
        
        /* obtain repeat info */
        if (!GetRegKeyInt(strFileConfig,
            "SENDINFO", 
            "REPEAT", 
            0,
            &bRepeat))
        {
            bRepeat = 0;
        }
        
        if (!GetRegKeyInt(strFileConfig,
            "SENDINFO", 
            "WRITEFILE", 
            0,
            &bWriteYUVFile))
        {
            printf("don't save the yuv file\n");
            bWriteYUVFile = 0;
        }

        bOK = TRUE;
    } while(0);

    if (3 == argc)
    {
        nSendSrcPort = atoi(argv[2]);
        printf("nSendSrcPort is %u\n", nSendSrcPort);
    }

    CEthFile cFileRead;

    s8 *strFileCap = achFilename;
    if (NULL != strFilename)
    {
        strFileCap = strFilename;
    }

    if (!cFileRead.Create(strFileCap))
    {
        return FALSE;
    }

    if (bOK)
    {
        cFileRead.SetFilter(inet_addr(achRcvSrcIp),
                            inet_addr(achRcvDstIp),
                            (u16)nSrcPort,
                            (u16)nDstPort);

		cFileRead.SetParam(bRepeat, bWriteYUVFile);

        do
        {
            if (SendProc(&cFileRead,
                         inet_addr(achSendDstIp),
                         (u16)nSendDstPort, 
                         inet_addr(achSendSrcIp),
                         (u16)nSendSrcPort) <= 0)
                break;
        } while (0);
    }
	else
	{
		//wait
		char aby[256];
		scanf("%s\n", aby);
	}

    printf("Game Over\n");
    
#ifdef WIN32
    WSACleanup();
#endif
    return TRUE;
    //getchar();
}