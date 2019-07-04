/*
 * varID.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __VAR_ID_H__
#define __VAR_ID_H__

// core (000)
#define F_FLOWDIR               0x00000001 // dir
#define F_DURATION              0x00000002 // duration
#define F_L4PROTO               0x00000003 // l4Proto

// basicFlow (010)
//#define F_DURATION              0x01000000 // duration
//#define F_L4PROTO               0x01000001 // l4Proto

// basicStats (020)
#define BL4_NUMPKTSSNT          0x02000000 // numPktsSnt
#define BL4_NUMPKTSRCVD         0x02000001 // numPktsRcvd
#define BL4_NUMBYTESSNT         0x02000002 // numBytesSnt
#define BL4_NUMBYTESRCVD        0x02000003 // numBytesRcvd
#define BL4_MINPKTSZ            0x02000004 // minPktSz
#define BL4_MAXPKTSZ            0x02000005 // maxPktSz
#define BL4_AVEPKTSIZE          0x02000006 // avePktSize
#define BL4_STDPKTSIZE          0x02000007 // stdPktSize
#define BL4_VARPKTSIZE          0x02000008 // varPktSize
#define BL4_PKTPS               0x02000009 // pktps
#define BL4_BYTPS               0x0200000a // bytps
#define BL4_PKTASM              0x0200000b // pktAsm
#define BL4_BYTASM              0x0200000c // bytAsm

// tcpFlags (030)
#define TFLG_IP_MINIDT          0x03000000 // ipMindIPID
#define TFLG_IP_MAXIDT          0x03000001 // ipMaxdIPID
#define TFLG_IP_MINTTLT         0x03000002 // ipMinTTL
#define TFLG_IP_MAXTTLT         0x03000003 // ipMaxTTL
#define TFLG_IP_TTLCHGT         0x03000004 // ipTTLChg
#define TFLG_IP_TOST            0x03000005 // ipTOS
#define TFLG_IP_FLGST           0x03000006 // ipFlags
#define TFLG_IP_OPTCNTT         0x03000007 // ipOptCnt

#define TFLG_TCP_PSEQCNT        0x03000008 // tcpPSeqCnt
#define TFLG_TCP_SSBYTES        0x03000009 // tcpSeqSntBytes
#define TFLG_TCP_SFLTCNTT       0x0300000a // tcpSeqFaultCnt
#define TFLG_TCP_ACNTT          0x0300000b // tcpPAckCnt
#define TFLG_TCP_FLWBYTES       0x0300000c // tcpFlwLssAckRcvdBytes
#define TFLG_TCP_AFLTCNTT       0x0300000d // tcpAckFaultCnt

#define TFLG_TCP_WINIT          0x0300000e // tcpInitWinSz
#define TFLG_TCP_WINAVET        0x0300000f // tcpAveWinSz
#define TFLG_TCP_WINMINT        0x03000010 // tcpMinWinSz
#define TFLG_TCP_WINMAXT        0x03000011 // tcpMaxWinSz
#define TFLG_TCP_WINDWNCNTT     0x03000012 // tcpWinSzDwnCnt
#define TFLG_TCP_WINUPCNTT      0x03000013 // tcpWinSzUpCnt
#define TFLG_TCP_WINCHGCNTT     0x03000014 // tcpWinSzChgDirCnt

#define TFLG_TCP_OPTPKTCNTT     0x03000015 // tcpOptPktCnt
#define TFLG_TCP_OPTCNTT        0x03000016 // tcpOptCnt
#define TFLG_TCP_MSST           0x03000017 // tcpMSS
#define TFLG_TCP_WINSCALE       0x03000018 // tcpWS

#define TFLG_TCP_TMS            0x03000019 // tcpTmS
#define TFLG_TCP_TMER           0x0300001a // tcpTmER

#define TFLG_TCP_RTT_T          0x0300001b // tcpSSASAATrip
#define TFLG_TCP_RTTATMIN       0x0300001c // tcpRTTAckTripMin
#define TFLG_TCP_RTTATMAX       0x0300001d // tcpRTTAckTripMax
#define TFLG_TCP_RTTATAVE       0x0300001e // tcpRTTAckTripAve
#define TFLG_TCP_RTTATJAVE      0x0300001f // tcpRTTAckTripJitAve

// sslDecode (047)
#define SSL_NUM_EXT             0x04700000 // sslNumExt
#define SSL_NUM_PROTO           0x04700001 // sslNumProto
#define SSL_NUM_CIPHER          0x04700002 // sslNumCipher
#define SSL_SESSIDLEN           0x04700003 // sslSessIdLen
#define SSL_TOR                 0x04700004 // sslTorFlow

// connectionCounter (080) [deprecated]
//#define CONNST_SIP              0x08000000 // connSrc
//#define CONNST_DIP              0x08000001 // connDst
//#define CONNST_SIPDIP           0x08000002 // connSrcDst

// connStat (081)
#define CONNST_SIP              0x08100000 // connSip
#define CONNST_DIP              0x08100001 // connDip
#define CONNST_SIPDIP           0x08100002 // connSipDip
#define CONNST_SIPDPRT          0x08100003 // connSipDprt
#define CONNST_F                0x08100004 // connF

// nFrstPkts (700)
//#define NF_SIG_L2L3L4PL         0x70000000 //
//#define NF_SIG_L2L3L4IAT        0x70000001 //

// descriptiveStats (810)
#define DS_PL_MIN               0x81000000 // MinPl
#define DS_PL_MAX               0x81000001 // MaxPl
#define DS_PL_MEAN              0x81000002 // MeanPl
#define DS_PL_LQUART            0x81000003 // LowQuartilePl
#define DS_PL_MED               0x81000004 // MedianPl
#define DS_PL_UQUART            0x81000005 // UppQuartilePl
#define DS_PL_IQD               0x81000006 // IqdPl
#define DS_PL_MODE              0x81000007 // ModePl
#define DS_PL_RNG               0x81000008 // RangePl
#define DS_PL_STDDEV            0x81000009 // StdPl
#define DS_PL_STDROB            0x8100000a // RobStdPl
#define DS_PL_SKEW              0x8100000b // SkewPl
#define DS_PL_EXCESS            0x8100000c // ExcPl

#define DS_IAT_MIN              0x8100000d // MinIat
#define DS_IAT_MAX              0x8100000e // MaxIat
#define DS_IAT_MEAN             0x8100000f // MeanIat
#define DS_IAT_LQUART           0x81000010 // LowQuartileIat
#define DS_IAT_MED              0x81000011 // MedianIat
#define DS_IAT_UQUART           0x81000012 // UppQuartileIat
#define DS_IAT_IQD              0x81000013 // IqdIat
#define DS_IAT_MODE             0x81000014 // ModeIat
#define DS_IAT_RNG              0x81000015 // RangeIat
#define DS_IAT_STDDEV           0x81000016 // StdIat
#define DS_IAT_STDROB           0x81000017 // RobStdIat
#define DS_IAT_SKEW             0x81000018 // SkewIat
#define DS_IAT_EXCESS           0x81000019 // ExcIat

// Unknown
#define VAR_UNKNOWN             0xffffffff // Not implemented

#endif // __VAR_ID_H__
