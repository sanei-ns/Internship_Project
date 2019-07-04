/*
 * hdrDesc.c
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

#include "hdrDesc.h"


#if T2_PRI_HDRDESC == 1

#include "global.h"

inline void t2_pktdesc_add_hdr(packet_t *pkt, const char *desc) {
    pkt->numHdrDesc++;
    if (UNLIKELY(pkt->status & HDOVRN)) return;
    const size_t dlen = strlen(desc);
    const size_t to_copy = MIN(sizeof(pkt->hdrDesc) - pkt->hdrDescPos - 1, dlen);
    memcpy(pkt->hdrDesc + pkt->hdrDescPos, desc, to_copy);
    if (LIKELY(to_copy == dlen)) {
        pkt->hdrDescPos += to_copy;
    } else {
        memcpy(pkt->hdrDesc + sizeof(pkt->hdrDesc) - 4, "...", 3);
        pkt->status |= HDOVRN;
    }
}


inline void t2_pktdesc_add_rephdr(packet_t *pkt, const char *desc, uint_fast8_t reps) {
#if T2_HDRDESC_AGGR == 0
    for (uint_fast32_t i = 0; i < reps; i++) {
        t2_pktdesc_add_hdr(pkt, desc);
    }
#else // T2_HDRDESC_AGGR == 1
    t2_pktdesc_add_hdr(pkt, desc);
    if (reps < 2) return;
    char num[6];
    snprintf(num, 6, "{%"PRIuFAST8"}", reps);
    t2_pktdesc_add_hdr(pkt, num);
    pkt->numHdrDesc += (reps - 2);
#endif // T2_HDRDESC_AGGR == 1
}


// TODO array l3proto[num]?
inline void t2_pktdesc_add_proto(packet_t *pkt, uint8_t proto) {
    switch (proto) {
        /* TODO peek into hopopts to get the next proto */
        case L3_HHOPT6:   t2_pktdesc_add_hdr(pkt, ":ipv6.hopopts"); break;
        case L3_ICMP:     t2_pktdesc_add_hdr(pkt, ":icmp");         break;
        /* TODO peek into type to get the next proto */
        case L3_IGMP:     t2_pktdesc_add_hdr(pkt, ":igmp");         break;
        case L3_IPIP4:    t2_pktdesc_add_hdr(pkt, ":ipv4");         break;
        case L3_TCP:      t2_pktdesc_add_hdr(pkt, ":tcp");          break;
        case L3_EGP:      t2_pktdesc_add_hdr(pkt, ":egp");          break;
        case L3_IGP:      t2_pktdesc_add_hdr(pkt, ":igp");          break;
        case L3_UDP:      t2_pktdesc_add_hdr(pkt, ":udp");          break;
        case L3_DCCP:     t2_pktdesc_add_hdr(pkt, ":dccp");         break;
        case L3_XTP:      t2_pktdesc_add_hdr(pkt, ":xtp");          break;
        case L3_DDP:      t2_pktdesc_add_hdr(pkt, ":ddp");          break;
        case L3_IPIP6:    t2_pktdesc_add_hdr(pkt, ":ipv6");         break;
        case L3_ROUT6:    t2_pktdesc_add_hdr(pkt, ":ipv6.routing"); break;
        /* TODO peek into fraghdr to get the next proto */
        case L3_FRAG6:    t2_pktdesc_add_hdr(pkt, ":ipv6.fraghdr"); break;
        case L3_IDRP:     t2_pktdesc_add_hdr(pkt, ":idrp");         break;
        case L3_NXTH6:    /* No Next-Header */                      break;
        case L3_DOPT6:    t2_pktdesc_add_hdr(pkt, ":ipv6.dstopts"); break;
        case L3_RSVP:     t2_pktdesc_add_hdr(pkt, ":rsvp");         break;
        case L3_GRE:      t2_pktdesc_add_hdr(pkt, ":gre");          break;
        /* TODO peek into dst to get the next proto */
        case L3_DSR:      t2_pktdesc_add_hdr(pkt, ":dsr");          break;
        case L3_ESP:      t2_pktdesc_add_hdr(pkt, ":esp");          break;
        /* TODO peek into ah to get the next proto */
        case L3_AH:       t2_pktdesc_add_hdr(pkt, ":ah");           break;
        case L3_SWIPE:    t2_pktdesc_add_hdr(pkt, ":swipe");        break;
        case L3_NHRP:     t2_pktdesc_add_hdr(pkt, ":nhrp");         break;
        case L3_ICMP6:    t2_pktdesc_add_hdr(pkt, ":icmpv6");       break;
        case L3_OSI:      t2_pktdesc_add_hdr(pkt, ":osi");          break;
        case L3_VINES:    t2_pktdesc_add_hdr(pkt, ":vines");        break;
        case L3_EIGRP:    t2_pktdesc_add_hdr(pkt, ":eigrp");        break;
        case L3_OSPF:     t2_pktdesc_add_hdr(pkt, ":ospf");         break;
        case L3_AX25:     t2_pktdesc_add_hdr(pkt, ":ax25");         break;
        case L3_ETHIP:    t2_pktdesc_add_hdr(pkt, ":etherip");      break;
        case L3_PIM:      t2_pktdesc_add_hdr(pkt, ":pim");          break;
        /* TODO peek into ipcomp to get the next proto */
        case L3_IPCOMP:   t2_pktdesc_add_hdr(pkt, ":ipcomp");       break;
        case L3_VRRP:     t2_pktdesc_add_hdr(pkt, ":vrrp");         break;
        case L3_PGM:      t2_pktdesc_add_hdr(pkt, ":pgm");          break;
        case L3_L2TP:     t2_pktdesc_add_hdr(pkt, ":l2tp");         break;
        case L3_SCTP:     t2_pktdesc_add_hdr(pkt, ":sctp");         break;
        case L3_RSVPE2EI: t2_pktdesc_add_hdr(pkt, ":rsvp-e2ei");    break;
        case L3_MOB6:     t2_pktdesc_add_hdr(pkt, ":mipv6");        break;
        case L3_UDPLITE:  t2_pktdesc_add_hdr(pkt, ":udplite");      break;
        /* TODO jump over mpls to get the next proto */
        case L3_MPLSIP:   t2_pktdesc_add_hdr(pkt, ":mpls");         break;
        case L3_HIP:      t2_pktdesc_add_hdr(pkt, ":hip");          break;
        case L3_SHIM6:    t2_pktdesc_add_hdr(pkt, ":shim6");        break;
        default: {
            char unk[10];
            snprintf(unk, 10, ":UNK(%"PRIu8")", proto);
            t2_pktdesc_add_hdr(pkt, unk);
            T2_SET_STATUS(pkt, STPDSCT);
            break;
        }
    }
}


inline void t2_pktdesc_add_ethproto(packet_t *pkt, uint16_t proto) {
    switch (proto) {
        case ETHERTYPE_LLC_WLCCPn:      t2_pktdesc_add_hdr(pkt, ":wlccp");    break;
        case ETHERTYPE_IDPn:            t2_pktdesc_add_hdr(pkt, ":idp");      break;
        case ETHERTYPE_IPn:             t2_pktdesc_add_hdr(pkt, ":ipv4");     break;
        case ETHERTYPE_CDPn:            t2_pktdesc_add_hdr(pkt, ":cdp");      break;
        case ETHERTYPE_VLANn:           t2_pktdesc_add_hdr(pkt, ":vlan");     break;
        case ETHERTYPE_LOOPn:           t2_pktdesc_add_hdr(pkt, ":loop");     break;
        case ETHERTYPE_NHRPn:           t2_pktdesc_add_hdr(pkt, ":nhrp");     break;
        case ETHERTYPE_CFMn:            t2_pktdesc_add_hdr(pkt, ":cfm");      break;
        case ETHERTYPE_VTPn:            t2_pktdesc_add_hdr(pkt, ":vtp");      break;
        case ETHERTYPE_DEC_DNAn:        t2_pktdesc_add_hdr(pkt, ":dec_dna");  break;
        case ETHERTYPE_PAGPn:           t2_pktdesc_add_hdr(pkt, ":pagp");     break;
        case ETHERTYPE_DTPn:            t2_pktdesc_add_hdr(pkt, ":dtp");      break;
        case ETHERTYPE_LATn:            t2_pktdesc_add_hdr(pkt, ":lat");      break;
        case ETHERTYPE_ARPn:            t2_pktdesc_add_hdr(pkt, ":arp");      break;
        case ETHERTYPE_FCoEn:           t2_pktdesc_add_hdr(pkt, ":fcoe");
                                        t2_pktdesc_add_hdr(pkt, ":fc");       break;
        case ETHERTYPE_SLOWn:           t2_pktdesc_add_hdr(pkt, ":slow");     break;
        case ETHERTYPE_PVSTPn:          t2_pktdesc_add_hdr(pkt, ":stp");      break;
        case ETHERTYPE_PPPn:            t2_pktdesc_add_hdr(pkt, ":ppp");      break;
        case ETHERTYPE_TDLSn:           t2_pktdesc_add_hdr(pkt, ":wlan");     break;
        case ETHERTYPE_UDLDn:           t2_pktdesc_add_hdr(pkt, ":udld");     break;
        case ETHERTYPE_IPCPn:           t2_pktdesc_add_hdr(pkt, ":ipcp");     break;
        case ETHERTYPE_LCPn:            t2_pktdesc_add_hdr(pkt, ":lcp");      break;
        case ETHERTYPE_CHAPn:           t2_pktdesc_add_hdr(pkt, ":chap");     break;
        case ETHERTYPE_CBCPn:           t2_pktdesc_add_hdr(pkt, ":cbcp");     break;
        case ETHERTYPE_WLCCPn:          t2_pktdesc_add_hdr(pkt, ":wlccp");    break;
        case ETHERTYPE_RARPn:           t2_pktdesc_add_hdr(pkt, ":rarp");     break;
        case ETHERTYPE_IPXn:            t2_pktdesc_add_hdr(pkt, ":ipx");      break;
        case ETHERTYPE_DEC_STPn:        t2_pktdesc_add_hdr(pkt, ":dec_stp");  break;
        case ETHERTYPE_WCCPn:           t2_pktdesc_add_hdr(pkt, ":wccp");     break;
        case ETHERTYPE_MPLS_UNICASTn:   t2_pktdesc_add_hdr(pkt, ":mpls");     break;
        case ETHERTYPE_MPLS_MULTICASTn: t2_pktdesc_add_hdr(pkt, ":mpls");     break;
        case ETHERTYPE_TEBn:            t2_pktdesc_add_hdr(pkt, ":eth");      break;
        case ETHERTYPE_DEC_MOPn:        t2_pktdesc_add_hdr(pkt, ":dec_mop");  break;
        case ETHERTYPE_PPPoE_Dn:        t2_pktdesc_add_hdr(pkt, ":pppoed");   break;
        case ETHERTYPE_PPPoE_Sn:        t2_pktdesc_add_hdr(pkt, ":pppoes");   break;
        case ETHERTYPE_MS_NLBn:         t2_pktdesc_add_hdr(pkt, ":msnlb");    break;
        case ETHERTYPE_JUMBO_LLCn:      t2_pktdesc_add_hdr(pkt, ":llc");      break;
        case ETHERTYPE_EAPOLn:          t2_pktdesc_add_hdr(pkt, ":eapol");    break;
        case ETHERTYPE_DDPn:            t2_pktdesc_add_hdr(pkt, ":ddp");      break;
        case ETHERTYPE_NDP_Fn:          t2_pktdesc_add_hdr(pkt, ":ndp");      break;
        case ETHERTYPE_NDP_Sn:          t2_pktdesc_add_hdr(pkt, ":ndp");      break;
        case ETHERTYPE_AOEn:            t2_pktdesc_add_hdr(pkt, ":aoe");      break;
        case ETHERTYPE_QINQn:           t2_pktdesc_add_hdr(pkt, ":vlan");     break;
        /* TODO peek into protocol field to get the next proto */
        case ETHERTYPE_VINES_IPn:       t2_pktdesc_add_hdr(pkt, ":vines_ip"); break;
        case ETHERTYPE_EDPn:            t2_pktdesc_add_hdr(pkt, ":edp");      break;
        case ETHERTYPE_LWAPPn:          t2_pktdesc_add_hdr(pkt, ":lwapp");    break;
        case ETHERTYPE_ERSPANn:         t2_pktdesc_add_hdr(pkt, ":erspan");   break;
        case ETHERTYPE_LLDPn:           t2_pktdesc_add_hdr(pkt, ":lldp");     break;
        case ETHERTYPE_IPV6n:           t2_pktdesc_add_hdr(pkt, ":ipv6");     break;
        case ETHERTYPE_AARPn:           t2_pktdesc_add_hdr(pkt, ":aarp");     break;
        case ETHERTYPE_CCPn:            t2_pktdesc_add_hdr(pkt, ":ccp");      break;
        case ETHERTYPE_PTPn:            t2_pktdesc_add_hdr(pkt, ":ptp");      break;
        default: {
            char unk[13];
            snprintf(unk, 13, ":UNK(0x%04"PRIx16")", proto);
            t2_pktdesc_add_hdr(pkt, unk);
            T2_SET_STATUS(pkt, STPDSCT);
            break;
        }
    }
}


inline void t2_pktdesc_add_llcproto(packet_t *pkt, uint8_t proto) {
    switch (proto) {
        case LLC_SAP_NULL:                                            break; // Individual
        case LLC_SAP_NULL+1:                                          break; // Group
        case LLC_SAP_LLC:                                             break;
        case LLC_SAP_SNA_PATH: t2_pktdesc_add_hdr(pkt, ":sna");       break;
        case LLC_SAP_IP:                                              break;
        case LLC_SAP_SNA1:     t2_pktdesc_add_hdr(pkt, ":sna");       break;
        case LLC_SAP_SNA2:     t2_pktdesc_add_hdr(pkt, ":sna");       break;
        //case LLC_SAP_PNM:      t2_pktdesc_add_hdr(pkt, ":");          break;
        case LLC_SAP_NETWARE1: t2_pktdesc_add_hdr(pkt, ":ipx");       break;
        case LLC_SAP_OSINL1:   t2_pktdesc_add_hdr(pkt, ":osi");       break;
        //case LLC_SAP_TI:       t2_pktdesc_add_hdr(pkt, ":");          break;
        case LLC_SAP_OSINL2:   t2_pktdesc_add_hdr(pkt, ":osi");       break;
        case LLC_SAP_OSINL3:   t2_pktdesc_add_hdr(pkt, ":osi");       break;
        case LLC_SAP_SNA3:     t2_pktdesc_add_hdr(pkt, ":sna");       break;
        case LLC_SAP_BSPAN:    t2_pktdesc_add_hdr(pkt, ":stp");       break;
        case LLC_SAP_OSINL4:   t2_pktdesc_add_hdr(pkt, ":osi");       break;
        //case LLC_SAP_MMS:      t2_pktdesc_add_hdr(pkt, ":");          break;
        case LLC_SAP_8208:     t2_pktdesc_add_hdr(pkt, ":x25");       break;
        case LLC_SAP_3COM:     t2_pktdesc_add_hdr(pkt, ":3comxns");   break;
        case LLC_SAP_BACNET:   t2_pktdesc_add_hdr(pkt, ":bacnet");    break;
        //case LLC_SAP_NESTAR:   t2_pktdesc_add_hdr(pkt, ":");          break;
        //case LLC_SAP_PRO:      t2_pktdesc_add_hdr(pkt, ":");          break;
        //case LLC_SAP_ARP:      t2_pktdesc_add_hdr(pkt, ":");          break;
        case LLC_SAP_SNAP:                                            break;
        //case LLC_SAP_HPJD:     t2_pktdesc_add_hdr(pkt, ":");          break;
        //case LLC_SAP_VINES1:   t2_pktdesc_add_hdr(pkt, ":");          break;
        case LLC_SAP_VINES2:   t2_pktdesc_add_hdr(pkt, ":vines_llc"); break;
        case LLC_SAP_SNA4:     t2_pktdesc_add_hdr(pkt, ":sna");       break;
        case LLC_SAP_IPX:      t2_pktdesc_add_hdr(pkt, ":ipx");       break;
        case LLC_SAP_NETBEUI:  t2_pktdesc_add_hdr(pkt, ":netbios");   break;
        //case LLC_SAP_LANMGR:   t2_pktdesc_add_hdr(pkt, ":");          break;
        case LLC_SAP_IMPL:     t2_pktdesc_add_hdr(pkt, ":hpext");     break;
        //case LLC_SAP_UB:       t2_pktdesc_add_hdr(pkt, ":");          break;
        case LLC_SAP_DISC:     t2_pktdesc_add_hdr(pkt, ":rpl");       break;
        case LLC_SAP_OSI:      t2_pktdesc_add_hdr(pkt, ":osi");       break;
        //case LLC_SAP_LAR:      t2_pktdesc_add_hdr(pkt, ":");          break;
        //case LLC_SAP_RM:       t2_pktdesc_add_hdr(pkt, ":");          break;
        case LLC_SAP_GLOBAL:                                          break;
        default: {
            char unk[11];
            snprintf(unk, 11, ":UNK(0x%02"PRIx8")", proto);
            t2_pktdesc_add_hdr(pkt, unk);
            T2_SET_STATUS(pkt, STPDSCT);
            break;
        }
    }
}


inline void t2_pktdesc_add_pppproto(packet_t *pkt, uint16_t proto) {
    switch (proto) {
        case PPP_IP4n:        t2_pktdesc_add_hdr(pkt, ":ipv4");      break;
        case PPP_IPCPn:       t2_pktdesc_add_hdr(pkt, ":ipcp");      break;
        case PPP_LCPn:        t2_pktdesc_add_hdr(pkt, ":lcp");       break;
        case PPP_OSIn:        t2_pktdesc_add_hdr(pkt, ":osi");       break;
        case PPP_PAPn:        t2_pktdesc_add_hdr(pkt, ":pap");       break;
        case PPP_CHAPn:       t2_pktdesc_add_hdr(pkt, ":chap");      break;
        case PPP_MPn:         t2_pktdesc_add_hdr(pkt, ":ppp");
                              t2_pktdesc_add_hdr(pkt, ":mp");        break;
        case PPP_IP6n:        t2_pktdesc_add_hdr(pkt, ":ipv6");      break;
        case PPP_MPLS_UCASTn: t2_pktdesc_add_hdr(pkt, ":mpls");      break;
        case PPP_MPLS_MCASTn: t2_pktdesc_add_hdr(pkt, ":mpls");      break;
        case PPP_COMPRESSn:   t2_pktdesc_add_hdr(pkt, ":comp_data"); break;
        case PPP_CCPn:        t2_pktdesc_add_hdr(pkt, ":ccp");       break;
        default: {
            char unk[13];
            snprintf(unk, 13, ":UNK(0x%04"PRIx16")", proto);
            t2_pktdesc_add_hdr(pkt, unk);
            T2_SET_STATUS(pkt, STPDSCT);
            break;
        }
    }
}

#endif // T2_PRI_HDRDESC == 1
