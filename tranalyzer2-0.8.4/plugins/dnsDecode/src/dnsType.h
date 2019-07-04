/*
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

#ifndef __DNSTYPE_H__
#define __DNSTYPE_H__

// local defines

// Type codes
#define DNS_A          0x0001 // a host address
#define DNS_NS         0x0002 // an authoritative name server
#define DNS_MD         0x0003 // a mail destination (OBSOLETE - use MX)
#define DNS_MF         0x0004 // a mail forwarder (OBSOLETE - use MX)
#define DNS_CNAME      0x0005 // the canonical name for an alias
#define DNS_SOA        0x0006 // marks the start of a zone of authority
#define DNS_MB         0x0007 // a mailbox domain name (EXPERIMENTAL)
#define DNS_MG         0x0008 // a mail group member (EXPERIMENTAL)
#define DNS_MR         0x0009 // a mail rename domain name (EXPERIMENTAL)
#define DNS_NULL       0x000A // a null RR (EXPERIMENTAL)
#define DNS_WKS        0x000B // a well known service description
#define DNS_PTR        0x000C // a domain name pointer
#define DNS_HINFO      0x000D // host information
#define DNS_MINFO      0x000E // mailbox or mail list information
#define DNS_MX         0x000F // mail exchange
#define DNS_TXT        0x0010 // text strings
#define DNS_RP         0x0011 // for Responsible Person
#define DNS_AFSDB      0x0012 // for AFS Data Base location
#define DNS_X25        0x0013 // for X.25 PSDN address
#define DNS_ISDN       0x0014 // for ISDN address
#define DNS_RT         0x0015 // for Route Through
#define DNS_NSAP       0x0016 // for NSAP address, NSAP style A record
#define DNS_NSAPPTR    0x0017 // for domain name pointer, NSAP style
#define DNS_SIG        0x0018 // for security signature
#define DNS_KEY        0x0019 // for security key
#define DNS_PX         0x001A // X.400 mail mapping information
#define DNS_GPOS       0x001B // Geographical Position
#define DNS_AAAA       0x001C // IP6 Address
#define DNS_LOC        0x001D // Location Information
#define DNS_NXT        0x001E // Next Domain (OBSOLETE)
#define DNS_EID        0x001F // Endpoint Identifier
#define DNS_NIMLOC     0x0020 // Nimrod Locator
#define DNS_SRV        0x0021 // Server Selection
#define DNS_ATMA       0x0022 // ATM Address
#define DNS_NAPTR      0x0023 // Naming Authority Pointer
#define DNS_KX         0x0024 // Key Exchanger
#define DNS_CERT       0x0025 // CERT
#define DNS_A6         0x0026 // A6 (OBSOLETE - use AAAA)
#define DNS_DNAME      0x0027 // DNAME
#define DNS_SINK       0x0028 // SINK
#define DNS_OPT        0x0029 // OPT
#define DNS_APL        0x002A // APL
#define DNS_DS         0x002B // Delegation Signer
#define DNS_SSHFP      0x002C // SSH Key Fingerprint
#define DNS_IPSECKEY   0x002D // IPSECKEY
#define DNS_RRSIG      0x002E // RRSIG
#define DNS_NSEC       0x002F // NSEC
#define DNS_DNSKEY     0x0030 // DNSKEY
#define DNS_DHCID      0x0031 // DHCID
#define DNS_NSEC3      0x0032 // NSEC3
#define DNS_NSEC3PAR   0x0033 // NSEC3PARAM
#define DNS_TLSA       0x0034 // TLSA
#define DNS_SMIMEA     0x0035 // S/MIME cert association
#define DNS_HIP        0x0037 // Host Identity Protocol
#define DNS_NINFO      0x0038 // NINFO
#define DNS_RKEY       0x0039 // RKEY
#define DNS_TALINK     0x003A // Trust Anchor LINK
#define DNS_CDS        0x003B // Child DS
#define DNS_CDNSKEY    0x003C // DNSKEY(s) the Child wants reflected in DS
#define DNS_OPENPGPKEY 0x003D // OpenPGP Key
#define DNS_CSYNC      0x003E // Child-To-Parent Synchronization
#define DNS_SPF        0x0063 //
#define DNS_UINFO      0x0064 //
#define DNS_UID        0x0065 //
#define DNS_GID        0x0066 //
#define DNS_UNSPEC     0x0067 //
#define DNS_NID        0x0068 //
#define DNS_L32        0x0069 //
#define DNS_L64        0x006A //
#define DNS_LP         0x006B //
#define DNS_EUI48      0x006C // an EUI-48 address
#define DNS_EUI64      0x006D // an EUI-64 address
#define DNS_TKEY       0x00F9 // Transaction Key
#define DNS_TSIG       0x00FA // Transaction Signature
#define DNS_IXFR       0x00FB // incremental transfer
#define DNS_AXFR       0x00FC // transfer of an entire zone
#define DNS_MAILB      0x00FD // mailbox-related RRs (MB, MG or MR)
#define DNS_MAILA      0x00FE // mail agent RRs (OBSOLETE - see MX)
#define DNS_ZONEALL    0x00FF // A request for all records the server/cache has available
#define DNS_URI        0x0100 // URI
#define DNS_CAA        0x0101 // Certification Authority Restriction
#define DNS_TA         0x8000 // DNSSEC Trust Authorities
#define DNS_DLV        0x8001 // DNSSEC Lookaside Validation

#endif // __DNSTYPE_H__
