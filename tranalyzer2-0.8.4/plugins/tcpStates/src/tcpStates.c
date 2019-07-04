/*
 * tcpStates.c
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

#include "tcpStates.h"


// Global variables

tcp_connection_t *tcp_connections;


// Static variables

static uint8_t tcpStatesAFlags;


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("tcpStates", "0.8.4", 0, 8);


void initialize() {

    if (UNLIKELY(!(tcp_connections = calloc(mainHashMap->hashChainTableSize, sizeof(tcp_connection_t))))) {
        T2_PERR("tcpState", "failed to allocate memory for tcp_connections");
        exit(-1);
    }

    // register timeouts
    timeout_handler_add(TIMEOUT_RESET);
    timeout_handler_add(TIMEOUT_NEW);
    timeout_handler_add(TIMEOUT_ESTABLISHED);
    timeout_handler_add(TIMEOUT_CLOSING);
    timeout_handler_add(TIMEOUT_CLOSED);
}


binary_value_t* printHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv, "tcpStates", "TCP state machine anomalies");
    return bv;
}


void onFlowGenerated(packet_t *packet __attribute__((unused)), unsigned long flowIndex) {
    // reset entry
    memset(&tcp_connections[flowIndex], '\0', sizeof(tcp_connection_t));
}


/*
 * The general state machine approach, not optimized
 * WHY our state machine differs from the "normal" TCP state machine?
 * Because we're sitting somewhere in the middle.
 * This leads to several special cases like
 * - recognizing already opened connections
 * - getting not every packet
 * - seeing only on side of a connection
 * and the most important one:
 * - We don't know the behavior of the internal tcp state machines inside the hosts
 */
void claimLayer4Information(packet_t *packet, unsigned long flowIndex) {

    if (packet->layer4Type != L3_TCP) return;

    // Only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    flow_t *flow = &flows[flowIndex];
    tcp_connection_t *conn = &tcp_connections[flowIndex];

    // Reverse flow
    flow_t *rev_flow;
    tcp_connection_t *rev_conn;
    if (flow->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        rev_flow = &flows[flow->oppositeFlowIndex];
        rev_conn = &tcp_connections[flow->oppositeFlowIndex];
    } else {
        rev_flow = NULL;
        rev_conn = NULL;
    }

    const tcpHeader_t * const tcpHeader = (tcpHeader_t*)&(packet->layer4Header->tcpHeader);
    const uint8_t tcpFlags = *((uint8_t*)tcpHeader + 13);

    // Null / Christmas scan
    if (((tcpFlags & TH_ALL_FLAGS) == TH_XMAS) ||
        ((tcpFlags & TH_ALL_FLAGS) == TH_NULL))
    {
        conn->anomalies |= EVIL;
    }

    switch (conn->state) {

        case STATE_NEW:

            // SYN
            if ((tcpFlags & TH_SYN_FIN_RST) == TH_SYN) {
                conn->syn_seen = 1;
                conn->syn_seq_num = ntohl(tcpHeader->seq);
                flow->timeout = TIMEOUT_NEW;

                // SYN-ACK
                if ((tcpFlags & TH_ACK) == TH_ACK) {
                    // packet ACKs a SYN from the opposite flow
                    if (rev_flow) {
                        // check ACK number
                        if (ntohl(tcpHeader->ack_seq) == rev_conn->syn_seq_num+1) {
                            rev_conn->syn_ackd = 1;
                        } else {
                            // ACK number is wrong -> bogus connection establishment
                            // go into STATE ESTABLISHED and set bogus bit zero
                            conn->state = STATE_ESTABLISHED;
                            flow->timeout = TIMEOUT_ESTABLISHED;
                            conn->anomalies |= MAL_CON_EST;

                            rev_conn->state = STATE_ESTABLISHED;
                            rev_flow->timeout = TIMEOUT_ESTABLISHED;
                            rev_conn->anomalies |= MAL_CON_EST;
                        }
                    } else {
                        // There is no opposite flow, maybe we don't see it
                        // -> set bogus flag zero and set the connection to established
                        conn->state = STATE_ESTABLISHED;
                        flow->timeout = TIMEOUT_ESTABLISHED;
                        conn->anomalies |= MAL_CON_EST;
                    }
                }
                break;
            }

            // ACK - Last part of 3 way or simultaneous handshake
            if (rev_flow && (tcpFlags & TH_ARSF) == TH_ACK) {
                if (ntohl(tcpHeader->ack_seq) == rev_conn->syn_seq_num+1) {
                    // correct ACK
                    rev_conn->syn_ackd = 1;
                    // check if own SYN packet was ACKed
                    if (conn->syn_ackd == 1) {
                        // connection successfully established -> change to state ESTABLISHED
                        conn->state = STATE_ESTABLISHED;
                        flow->timeout = TIMEOUT_ESTABLISHED;
                        rev_conn->state = STATE_ESTABLISHED;
                        rev_flow->timeout = TIMEOUT_ESTABLISHED;
                    }
                } else {
                    // there's something wrong with the ACK number:
                    // set anomaly flag and set flow to state ESTABLISHED
                    conn->state = STATE_ESTABLISHED;
                    flow->timeout = TIMEOUT_ESTABLISHED;
                    conn->anomalies |= MAL_CON_EST;

                    rev_conn->state = STATE_ESTABLISHED;
                    rev_flow->timeout = TIMEOUT_ESTABLISHED;
                    rev_conn->anomalies |= MAL_CON_EST;
                }
                break;
            }

            /*
             * RST, ACK flags set, opposite flow
             * Normal connection rejection
             */
            if (rev_flow && ((tcpFlags & TH_ARSF) == TH_RST_ACK)) {
                // reset flow
                conn->state = STATE_RESET;
                flow->timeout = TIMEOUT_RESET;
                conn->anomalies |= RST_TRANS; // Reset from sender seen
                // reset opposite flow
                rev_conn->state = STATE_RESET;
                rev_flow->timeout = TIMEOUT_RESET;
                break;
            }

            // Every other combination with RST flag
            if ((tcpFlags & TH_RST) == TH_RST) {
                // Reset from sender seen, malformed connection establishment
                conn->anomalies |= (RST_TRANS | MAL_CON_EST);
                conn->state = STATE_RESET;
                flow->timeout = TIMEOUT_RESET;

                if (rev_flow) {
                    // malformed connection establishment
                    // Some strange reset
                    rev_conn->anomalies |= MAL_CON_EST;
                    rev_conn->state = STATE_RESET;
                    rev_flow->timeout = TIMEOUT_RESET;
                } else {
                    // Possible RST scan
                    conn->anomalies |= EVIL;
                }
                break;
            }

            /*
             * A flow starts with a teardown. Possible reasons:
             * - We didn't see the previous packets of this connection.
             * - A FIN scan
             */
            if ((tcpFlags & TH_ARSF) == TH_FIN_ACK) {
                conn->fin_seen = 1;
                conn->fin_seq_num = ntohl(tcpHeader->seq);
                // The connection establishment is definitely malicious or was not seen
                conn->anomalies |= MAL_CON_EST;
                conn->state = STATE_CLOSING;
                flow->timeout = TIMEOUT_CLOSING;

                if (rev_flow) {
                    rev_conn->anomalies |= MAL_CON_EST; // malformed connection establishment

                    if (rev_conn->fin_seen && (rev_conn->fin_seq_num+1 == ntohl(tcpHeader->ack_seq))) {
                        rev_conn->fin_ackd = 1;
                    }
                } else {
                    // No opposite flow and this FIN packet is the first packet we see?
                    // That might be a FIN scan
                    conn->fin_scan = 1;
                }
                break;
            }

            if ((tcpFlags & TH_ARSF) == TH_FIN) {
                // This IS a FIN scan!
                conn->anomalies |= EVIL;
                break;
            }

            // Every other combination is bogus.
            // We set the state to ESTABLISHED, because there could be something interesting in the flows :)
            // TODO: Distinction between more states

            // Malformed connection establishment
            conn->state = STATE_ESTABLISHED;
            flow->timeout = TIMEOUT_ESTABLISHED;
            conn->anomalies |= MAL_CON_EST;

            if (rev_flow) {
                // Malformed connection establishment
                rev_conn->state = STATE_ESTABLISHED;
                rev_flow->timeout = TIMEOUT_ESTABLISHED;
                rev_conn->anomalies |= MAL_CON_EST;
            }
            break;

        case STATE_ESTABLISHED:
            // In this state should be no SYN flag seen or no ACK missing (even RST packets should ack)
            if ((tcpFlags & TH_SYN_ACK) != TH_ACK) {
                conn->anomalies |= MAL_FLGS_EST; // Malformed flags during established connection

                // Malformed flags during established connection
                if (rev_conn) rev_conn->anomalies |= MAL_FLGS_EST;
            }

            // sender initiates a teardown
            if ((tcpFlags & TH_FIN) == TH_FIN) {
                conn->fin_seen = 1;
                conn->fin_seq_num = ntohl(tcpHeader->seq);
                conn->state = STATE_CLOSING;
                flow->timeout = TIMEOUT_CLOSING;

                if (tcpHeader->ack && rev_conn && rev_conn->fin_seen &&
                    ntohl(tcpHeader->ack_seq) == rev_conn->fin_seq_num+1)
                {
                    rev_conn->fin_ackd = 1;
                }
            }

            // Connection has been reset
            if ((tcpFlags & TH_RST) == TH_RST) {
                // Reset from sender seen, malformed connection teardown
                conn->state = STATE_RESET;
                flow->timeout = TIMEOUT_RESET;
                conn->anomalies |= (RST_TRANS | MAL_TEARDWN);

                if (rev_flow) {
                    // Malformed connection teardown
                    rev_conn->state = STATE_RESET;
                    rev_flow->timeout = TIMEOUT_RESET;
                    rev_conn->anomalies |= MAL_TEARDWN;
                }
            }
            break;

        case STATE_CLOSING:

            // Connection has been reset
            if ((tcpFlags & TH_RST) == TH_RST) {
                // Reset from sender seen, malformed connection teardown
                conn->state = STATE_RESET;
                flow->timeout = TIMEOUT_RESET;
                conn->anomalies |= (RST_TRANS | MAL_TEARDWN);

                if (rev_flow) {
                    // Malformed connection teardown
                    rev_conn->state = STATE_RESET;
                    rev_flow->timeout = TIMEOUT_RESET;
                    rev_conn->anomalies |= MAL_TEARDWN;
                }
            }

            if ((tcpFlags & TH_ACK) == TH_ACK && rev_conn && rev_conn->fin_seen &&
                 ntohl(tcpHeader->ack_seq) == rev_conn->fin_seq_num+1)
            {
                rev_conn->fin_ackd = 1;
            }

            // Test if teardown is complete
            if (conn->fin_seen && conn->fin_ackd && rev_conn &&
                rev_conn->fin_seen && rev_conn->fin_ackd && rev_flow)
            {
                conn->state = STATE_CLOSED;
                flow->timeout = TIMEOUT_CLOSED;
                rev_conn->state = STATE_CLOSED;
                rev_flow->timeout = TIMEOUT_CLOSED;
            }
            break;

        case STATE_CLOSED:
            // more packets from sender after connection closing seen
            // A "normal" connection should not enter this state
            conn->anomalies |= PKTS_TERM;

            // Connection has been reset
            if ((tcpFlags & TH_RST) == TH_RST) {
                // Reset from sender seen, malformed connection teardown
                conn->state = STATE_RESET;
                flow->timeout = TIMEOUT_RESET;
                conn->anomalies |= (RST_TRANS | MAL_TEARDWN);

                if (rev_flow && rev_conn) {
                    // Malformed connection teardown
                    rev_conn->state = STATE_RESET;
                    rev_flow->timeout = TIMEOUT_RESET;
                    rev_conn->anomalies |= MAL_TEARDWN;
                }
            }
            break;

        case STATE_RESET:
            // More packets after reset seen
            conn->anomalies |= PKTS_RST;
            break;

        default:
            T2_PWRN("tcpStates", "Unhandled state '%hhu'", conn->state);
            break;
    }
}


#if BLOCK_BUF == 0
void onFlowTerminate(unsigned long flowIndex) {
    const flow_t * const flow = &flows[flowIndex];
    tcp_connection_t * const conn = &tcp_connections[flowIndex];

    if (flow->layer4Protocol != L3_TCP) {
        OUTBUF_APPEND_U8(main_output_buffer, conn->anomalies);
        return;
    }

    if (flow->oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        // Malformed connection establishment and teardown
        conn->anomalies |= (MAL_CON_EST | MAL_TEARDWN);
    } else {
        tcp_connection_t *rev_conn = &tcp_connections[flow->oppositeFlowIndex];

        // Malformed connection establishment
        if (!(conn->syn_seen && rev_conn->syn_seen &&
              conn->syn_ackd && rev_conn->syn_ackd))
        {
            conn->anomalies |= MAL_CON_EST;
        }

        // Malformed connection teardown
        if (!(conn->fin_seen && rev_conn->fin_seen &&
              conn->fin_ackd && rev_conn->fin_ackd))
        {
            conn->anomalies |= MAL_TEARDWN;
        } else {
            // A correct teardown implies that no fin scan was performed (see state NEW)
            conn->fin_scan = 0;
            rev_conn->fin_scan = 0;
        }
    }

    // If the fin scan bit is still set, set the possible evil behavior bit
    if (conn->fin_scan) conn->anomalies |= EVIL;

    tcpStatesAFlags |= conn->anomalies;

    // print states info
    OUTBUF_APPEND_U8(main_output_buffer, conn->anomalies);
}
#endif // BLOCK_BUF == 0


void pluginReport(FILE *stream) {
    if (tcpStatesAFlags) {
        T2_FPLOG(stream, "tcpStates", "Aggregated anomaly flags: 0x%02"B2T_PRIX8, tcpStatesAFlags);
    }
}


void onApplicationTerminate() {
    free(tcp_connections);
}
