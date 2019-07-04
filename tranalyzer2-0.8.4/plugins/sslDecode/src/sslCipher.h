/*
 * sslDecode.c
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

/*
 * References:
 *
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */

#ifndef __SSL_CIPHER_H__
#define __SSL_CIPHER_H__

// WEAK:
//   - All NULL ciphers
//   - All RC4  ciphers
//   - All EXPORT ciphers
//   - All anon ciphers

// 0x00-0xbf,*: reserved for IETF Standards Track Protocols
// 0xc0-0xfe,*: reserved for non-Standards Track methods
// 0xff     ,*: reserved for private use

#define TLS_NULL_WITH_NULL_NULL                         0x0000 // WEAK
#define TLS_RSA_WITH_NULL_MD5                           0x0001 // WEAK
#define TLS_RSA_WITH_NULL_SHA                           0x0002 // WEAK
#define TLS_RSA_EXPORT_WITH_RC4_40_MD5                  0x0003 // WEAK
#define TLS_RSA_WITH_RC4_128_MD5                        0x0004 // WEAK
#define TLS_RSA_WITH_RC4_128_SHA                        0x0005 // WEAK
#define TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5              0x0006 // WEAK
#define TLS_RSA_WITH_IDEA_CBC_SHA                       0x0007 // MEDIUM
#define TLS_RSA_EXPORT_WITH_DES40_CBC_SHA               0x0008 // WEAK
#define TLS_RSA_WITH_DES_CBC_SHA                        0x0009 // LOW
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA                   0x000a // HIGH
#define TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA            0x000b // WEAK
#define TLS_DH_DSS_WITH_DES_CBC_SHA                     0x000c // LOW
#define TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA                0x000d // HIGH
#define TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA            0x000e // WEAK
#define TLS_DH_RSA_WITH_DES_CBC_SHA                     0x000f // LOW
#define TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA                0x0010 // HIGH
#define TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA           0x0011 // WEAK
#define TLS_DHE_DSS_WITH_DES_CBC_SHA                    0x0012 // LOW
#define TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA               0x0013 // HIGH
#define TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA           0x0014 // WEAK
#define TLS_DHE_RSA_WITH_DES_CBC_SHA                    0x0015 // LOW
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA               0x0016 // HIGH
#define TLS_DH_anon_EXPORT_WITH_RC4_40_MD5              0x0017 // WEAK
#define TLS_DH_anon_WITH_RC4_128_MD5                    0x0018 // WEAK
#define TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA           0x0019 // WEAK
#define TLS_DH_anon_WITH_DES_CBC_SHA                    0x001a // WEAK
#define TLS_DH_anon_WITH_3DES_EDE_CBC_SHA               0x001b // WEAK
#define TLS_FZA_DMS_NULL_SHA                            0x001c // WEAK
#define TLS_FZA_DMS_FZA_SHA                             0x001d // MEDIUM
#define TLS_KRB5_WITH_DES_CBC_SHA                       0x001e // WEAK
#define TLS_KRB5_WITH_3DES_EDE_CBC_SHA                  0x001f // HIGH
#define TLS_KRB5_WITH_RC4_128_SHA                       0x0020 // WEAK
#define TLS_KRB5_WITH_IDEA_CBC_SHA                      0x0021 // MEDIUM
#define TLS_KRB5_WITH_DES_CBC_MD5                       0x0022 // LOW
#define TLS_KRB5_WITH_3DES_EDE_CBC_MD5                  0x0023 // HIGH
#define TLS_KRB5_WITH_RC4_128_MD5                       0x0024 // WEAK
#define TLS_KRB5_WITH_IDEA_CBC_MD5                      0x0025 // MEDIUM
#define TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA             0x0026 // WEAK
#define TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA             0x0027 // WEAK
#define TLS_KRB5_EXPORT_WITH_RC4_40_SHA                 0x0028 // WEAK
#define TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5             0x0029 // WEAK
#define TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5             0x002a // WEAK
#define TLS_KRB5_EXPORT_WITH_RC4_40_MD5                 0x002b // WEAK
#define TLS_PSK_WITH_NULL_SHA                           0x002c
#define TLS_DHE_PSK_WITH_NULL_SHA                       0x002d
#define TLS_RSA_PSK_WITH_NULL_SHA                       0x002e
#define TLS_RSA_WITH_AES_128_CBC_SHA                    0x002f // HIGH
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA                 0x0030 // MEDIUM
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA                 0x0031 // MEDIUM
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA                0x0032 // HIGH
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA                0x0033 // HIGH
#define TLS_DH_anon_WITH_AES_128_CBC_SHA                0x0034 // WEAK
#define TLS_RSA_WITH_AES_256_CBC_SHA                    0x0035 // HIGH
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA                 0x0036 // MEDIUM
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA                 0x0037 // MEDIUM
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA                0x0038 // HIGH
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA                0x0039 // HIGH
#define TLS_DH_anon_WITH_AES_256_CBC_SHA                0x003a // WEAK
#define TLS_RSA_WITH_NULL_SHA256                        0x003b // WEAK
#define TLS_RSA_WITH_AES_128_CBC_SHA256                 0x003c // HIGH
#define TLS_RSA_WITH_AES_256_CBC_SHA256                 0x003d // HIGH
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA256              0x003e // HIGH
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA256              0x003f // HIGH
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA256             0x0040 // HIGH
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA               0x0041 // HIGH
#define TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA            0x0042 // HIGH
#define TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA            0x0043 // HIGH
#define TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA           0x0044 // HIGH
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA           0x0045 // HIGH
#define TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA           0x0046 // WEAK
#define TLS_RSA_EXPORT1024_WITH_RC4_56_MD5              0x0060 // WEAK
#define TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5          0x0061 // WEAK
#define TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA             0x0062 // WEAK
#define TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA         0x0063 // WEAK
#define TLS_RSA_EXPORT1024_WITH_RC4_56_SHA              0x0064 // WEAK
#define TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA          0x0065 // WEAK
#define TLS_DHE_DSS_WITH_RC4_128_SHA                    0x0066 // WEAK
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256             0x0067 // HIGH
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA256              0x0068 // HIGH
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA256              0x0069 // HIGH
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA256             0x006a // HIGH
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256             0x006b // HIGH
#define TLS_DH_anon_WITH_AES_128_CBC_SHA256             0x006c // WEAK
#define TLS_DH_anon_WITH_AES_256_CBC_SHA256             0x006d // WEAK
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA               0x0084 // HIGH
#define TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA            0x0085 // HIGH
#define TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA            0x0086 // HIGH
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA           0x0087 // HIGH
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA           0x0088 // HIGH
#define TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA           0x0089 // WEAK
#define TLS_PSK_WITH_RC4_128_SHA                        0x008a // MEDIUM
#define TLS_PSK_WITH_3DES_EDE_CBC_SHA                   0x008b // HIGH
#define TLS_PSK_WITH_AES_128_CBC_SHA                    0x008c // HIGH
#define TLS_PSK_WITH_AES_256_CBC_SHA                    0x008d // HIGH
#define TLS_DHE_PSK_WITH_RC4_128_SHA                    0x008e
#define TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA               0x008f
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA                0x0090
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA                0x0091
#define TLS_RSA_PSK_WITH_RC4_128_SHA                    0x0092
#define TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA               0x0093
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA                0x0094
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA                0x0095
#define TLS_RSA_WITH_SEED_CBC_SHA                       0x0096 // MEDIUM
#define TLS_DH_DSS_WITH_SEED_CBC_SHA                    0x0097 // MEDIUM
#define TLS_DH_RSA_WITH_SEED_CBC_SHA                    0x0098 // MEDIUM
#define TLS_DHE_DSS_WITH_SEED_CBC_SHA                   0x0099 // MEDIUM
#define TLS_DHE_RSA_WITH_SEED_CBC_SHA                   0x009a // MEDIUM
#define TLS_DH_anon_WITH_SEED_CBC_SHA                   0x009b // WEAK
#define TLS_RSA_WITH_AES_128_GCM_SHA256                 0x009c // HIGH
#define TLS_RSA_WITH_AES_256_GCM_SHA384                 0x009d // HIGH
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256             0x009e // HIGH
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384             0x009f // HIGH
#define TLS_DH_RSA_WITH_AES_128_GCM_SHA256              0x00a0 // HIGH
#define TLS_DH_RSA_WITH_AES_256_GCM_SHA384              0x00a1 // HIGH
#define TLS_DHE_DSS_WITH_AES_128_GCM_SHA256             0x00a2 // HIGH
#define TLS_DHE_DSS_WITH_AES_256_GCM_SHA384             0x00a3 // HIGH
#define TLS_DH_DSS_WITH_AES_128_GCM_SHA256              0x00a4 // HIGH
#define TLS_DH_DSS_WITH_AES_256_GCM_SHA384              0x00a5 // HIGH
#define TLS_DH_anon_WITH_AES_128_GCM_SHA256             0x00a6 // WEAK
#define TLS_DH_anon_WITH_AES_256_GCM_SHA384             0x00a7 // WEAK
#define TLS_PSK_WITH_AES_128_GCM_SHA256                 0x00a8
#define TLS_PSK_WITH_AES_256_GCM_SHA384                 0x00a9
#define TLS_DHE_PSK_WITH_AES_128_GCM_SHA256             0x00aa
#define TLS_DHE_PSK_WITH_AES_256_GCM_SHA384             0x00ab
#define TLS_RSA_PSK_WITH_AES_128_GCM_SHA256             0x00ac
#define TLS_RSA_PSK_WITH_AES_256_GCM_SHA384             0x00ad
#define TLS_PSK_WITH_AES_128_CBC_SHA256                 0x00ae
#define TLS_PSK_WITH_AES_256_CBC_SHA384                 0x00af
#define TLS_PSK_WITH_NULL_SHA256                        0x00b0 // WEAK
#define TLS_PSK_WITH_NULL_SHA384                        0x00b1 // WEAK
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA256             0x00b2
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA384             0x00b3
#define TLS_DHE_PSK_WITH_NULL_SHA256                    0x00b4 // WEAK
#define TLS_DHE_PSK_WITH_NULL_SHA384                    0x00b5 // WEAK
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA256             0x00b6
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA384             0x00b7
#define TLS_RSA_PSK_WITH_NULL_SHA256                    0x00b8 // WEAK
#define TLS_RSA_PSK_WITH_NULL_SHA384                    0x00b9 // WEAK
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256            0x00ba
#define TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256         0x00bb
#define TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256         0x00bc
#define TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256        0x00bd
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256        0x00be
#define TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256        0x00bf // WEAK
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256            0x00c0 // HIGH
#define TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256         0x00c1
#define TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256         0x00c2
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256        0x00c3
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256        0x00c4
#define TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256        0x00c5 // WEAK
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV               0x00ff
#define TLS_DES_64_CBC_WITH_SHA                         0x0140 // LOW
#define TLS_DES_64_CFB64_WITH_MD5_1                     0x0800 // WEAK
#define TLS_ECDH_ECDSA_WITH_NULL_SHA                    0xc001 // WEAK
#define TLS_ECDH_ECDSA_WITH_RC4_128_SHA                 0xc002 // WEAK
#define TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA            0xc003 // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA             0xc004 // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA             0xc005 // HIGH
#define TLS_ECDHE_ECDSA_WITH_NULL_SHA                   0xc006 // WEAK
#define TLS_ECDHE_ECDSA_WITH_RC4_128_SHA                0xc007 // WEAK
#define TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA           0xc008 // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA            0xc009 // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA            0xc00a // HIGH
#define TLS_ECDH_RSA_WITH_NULL_SHA                      0xc00b // WEAK
#define TLS_ECDH_RSA_WITH_RC4_128_SHA                   0xc00c // WEAK
#define TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA              0xc00d // HIGH
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA               0xc00e // MEDIUM
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA               0xc00f // MEDIUM
#define TLS_ECDHE_RSA_WITH_NULL_SHA                     0xc010 // WEAK
#define TLS_ECDHE_RSA_WITH_RC4_128_SHA                  0xc011 // WEAK
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA             0xc012 // HIGH
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA              0xc013 // HIGH
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA              0xc014 // HIGH
#define TLS_ECDH_anon_WITH_NULL_SHA                     0xc015 // WEAK
#define TLS_ECDH_anon_WITH_RC4_128_SHA                  0xc016 // WEAK
#define TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA             0xc017 // WEAK
#define TLS_ECDH_anon_WITH_AES_128_CBC_SHA              0xc018 // WEAK
#define TLS_ECDH_anon_WITH_AES_256_CBC_SHA              0xc019 // WEAK
#define TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA               0xc01a // HIGH
#define TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA           0xc01b // HIGH
#define TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA           0xc01c // HIGH
#define TLS_SRP_SHA_WITH_AES_128_CBC_SHA                0xc01d // HIGH
#define TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA            0xc01e // HIGH
#define TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA            0xc01f // HIGH
#define TLS_SRP_SHA_WITH_AES_256_CBC_SHA                0xc020 // HIGH
#define TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA            0xc021 // HIGH
#define TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA            0xc022 // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256         0xc023 // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384         0xc024 // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256          0xc025 // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384          0xc026 // HIGH
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256           0xc027 // HIGH
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384           0xc028 // HIGH
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256            0xc029 // HIGH
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384            0xc02a // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256         0xc02b // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384         0xc02c // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256          0xc02d // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384          0xc02e // HIGH
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256           0xc02f // HIGH
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384           0xc030 // HIGH
#define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256            0xc031 // HIGH
#define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384            0xc032 // HIGH
#define TLS_ECDHE_PSK_WITH_RC4_128_SHA                  0xc033
#define TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA             0xc034
#define TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA              0xc035
#define TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA              0xc036
#define TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256           0xc037
#define TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384           0xc038
#define TLS_ECDHE_PSK_WITH_NULL_SHA                     0xc039 // WEAK
#define TLS_ECDHE_PSK_WITH_NULL_SHA256                  0xc03a // WEAK
#define TLS_ECDHE_PSK_WITH_NULL_SHA384                  0xc03b // WEAK
#define TLS_RSA_WITH_ARIA_128_CBC_SHA256                0xc03c
#define TLS_RSA_WITH_ARIA_256_CBC_SHA384                0xc03d
#define TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256             0xc03e
#define TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384             0xc03f
#define TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256             0xc040
#define TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384             0xc041
#define TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256            0xc042
#define TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384            0xc043
#define TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256            0xc044
#define TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384            0xc045
#define TLS_DH_anon_WITH_ARIA_128_CBC_SHA256            0xc046
#define TLS_DH_anon_WITH_ARIA_256_CBC_SHA384            0xc047
#define TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256        0xc048
#define TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384        0xc049
#define TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256         0xc04a
#define TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384         0xc04b
#define TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256          0xc04c
#define TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384          0xc04d
#define TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256           0xc04e
#define TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384           0xc04f
#define TLS_RSA_WITH_ARIA_128_GCM_SHA256                0xc050
#define TLS_RSA_WITH_ARIA_256_GCM_SHA384                0xc051
#define TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256            0xc052
#define TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384            0xc053
#define TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256             0xc054
#define TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384             0xc055
#define TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256            0xc056
#define TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384            0xc057
#define TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256             0xc058
#define TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384             0xc059
#define TLS_DH_anon_WITH_ARIA_128_GCM_SHA256            0xc05a // WEAK
#define TLS_DH_anon_WITH_ARIA_256_GCM_SHA384            0xc05b // WEAK
#define TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256        0xc05c
#define TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384        0xc05d
#define TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256         0xc05e
#define TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384         0xc05f
#define TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256          0xc060
#define TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384          0xc061
#define TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256           0xc062
#define TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384           0xc063
#define TLS_PSK_WITH_ARIA_128_CBC_SHA256                0xc064
#define TLS_PSK_WITH_ARIA_256_CBC_SHA384                0xc065
#define TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256            0xc066
#define TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384            0xc067
#define TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256            0xc068
#define TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384            0xc069
#define TLS_PSK_WITH_ARIA_128_GCM_SHA256                0xc06a
#define TLS_PSK_WITH_ARIA_256_GCM_SHA384                0xc06b
#define TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256            0xc06c
#define TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384            0xc06d
#define TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256            0xc06e
#define TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384            0xc06f
#define TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256          0xc070
#define TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384          0xc071
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256    0xc072
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384    0xc073
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256     0xc074
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384     0xc075
#define TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256      0xc076
#define TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384      0xc077
#define TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256       0xc078
#define TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384       0xc079
#define TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256            0xc07a
#define TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384            0xc07b
#define TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256        0xc07c
#define TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384        0xc07d
#define TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256         0xc07e
#define TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384         0xc07f
#define TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256        0xc080
#define TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384        0xc081
#define TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256         0xc082
#define TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384         0xc083
#define TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256        0xc084 // WEAK
#define TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384        0xc085 // WEAK
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256    0xc086
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384    0xc087
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256     0xc088
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384     0xc089
#define TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256      0xc08a
#define TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384      0xc08b
#define TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256       0xc08c
#define TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384       0xc08d
#define TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256            0xc08e
#define TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384            0xc08f
#define TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256        0xc090
#define TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384        0xc091
#define TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256        0xc092
#define TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384        0xc093
#define TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256            0xc094
#define TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384            0xc095
#define TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256        0xc096
#define TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384        0xc097
#define TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256        0xc098
#define TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384        0xc099
#define TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256      0xc09a
#define TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384      0xc09b
#define TLS_RSA_WITH_AES_128_CCM                        0xc09c // HIGH
#define TLS_RSA_WITH_AES_256_CCM                        0xc09d // HIGH
#define TLS_DHE_RSA_WITH_AES_128_CCM                    0xc09e // HIGH
#define TLS_DHE_RSA_WITH_AES_256_CCM                    0xc09f // HIGH
#define TLS_RSA_WITH_AES_128_CCM_8                      0xc0a0 // HIGH
#define TLS_RSA_WITH_AES_256_CCM_8                      0xc0a1 // HIGH
#define TLS_DHE_RSA_WITH_AES_128_CCM_8                  0xc0a2 // HIGH
#define TLS_DHE_RSA_WITH_AES_256_CCM_8                  0xc0a3 // HIGH
#define TLS_PSK_WITH_AES_128_CCM                        0xc0a4 // HIGH
#define TLS_PSK_WITH_AES_256_CCM                        0xc0a5 // HIGH
#define TLS_DHE_PSK_WITH_AES_128_CCM                    0xc0a6
#define TLS_DHE_PSK_WITH_AES_256_CCM                    0xc0a7
#define TLS_PSK_WITH_AES_128_CCM_8                      0xc0a8 // HIGH
#define TLS_PSK_WITH_AES_256_CCM_8                      0xc0a9 // HIGH
#define TLS_PSK_DHE_WITH_AES_128_CCM_8                  0xc0aa
#define TLS_PSK_DHE_WITH_AES_256_CCM_8                  0xc0ab
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM                0xc0ac // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM                0xc0ad // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8              0xc0ae // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8              0xc0af // HIGH
#define TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_1            0xfee0 // HIGH
#define TLS_RSA_FIPS_WITH_DES_CBC_SHA_1                 0xfee1 // LOW
#define TLS_RSA_FIPS_WITH_DES_CBC_SHA_2                 0xfefe // LOW
#define TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2            0xfeff // HIGH

#define SSL_FLAG_WEAK_CIPHER(ssl, c) \
    switch ((c)) { \
        case TLS_NULL_WITH_NULL_NULL: \
        case TLS_RSA_WITH_NULL_MD5: \
        case TLS_RSA_WITH_NULL_SHA: \
        case TLS_RSA_EXPORT_WITH_RC4_40_MD5: \
        case TLS_RSA_WITH_RC4_128_MD5: \
        case TLS_RSA_WITH_RC4_128_SHA: \
        case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5: \
        case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA: \
        case TLS_RSA_WITH_DES_CBC_SHA: \
        case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA: \
        case TLS_DH_DSS_WITH_DES_CBC_SHA: \
        case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA: \
        case TLS_DH_RSA_WITH_DES_CBC_SHA: \
        case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA: \
        case TLS_DHE_DSS_WITH_DES_CBC_SHA: \
        case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: \
        case TLS_DHE_RSA_WITH_DES_CBC_SHA: \
        case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5: \
        case TLS_DH_anon_WITH_RC4_128_MD5: \
        case TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA: \
        case TLS_DH_anon_WITH_DES_CBC_SHA: \
        case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA: \
        case TLS_FZA_DMS_NULL_SHA: \
        case TLS_KRB5_WITH_DES_CBC_SHA: \
        case TLS_KRB5_WITH_RC4_128_SHA: \
        case TLS_KRB5_WITH_DES_CBC_MD5: \
        case TLS_KRB5_WITH_RC4_128_MD5: \
        case TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA: \
        case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA: \
        case TLS_KRB5_EXPORT_WITH_RC4_40_SHA: \
        case TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5: \
        case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5: \
        case TLS_KRB5_EXPORT_WITH_RC4_40_MD5: \
        case TLS_DH_anon_WITH_AES_128_CBC_SHA: \
        case TLS_DH_anon_WITH_AES_256_CBC_SHA: \
        case TLS_RSA_WITH_NULL_SHA256: \
        case TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA: \
        case TLS_RSA_EXPORT1024_WITH_RC4_56_MD5: \
        case TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5: \
        case TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA: \
        case TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA: \
        case TLS_RSA_EXPORT1024_WITH_RC4_56_SHA: \
        case TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA: \
        case TLS_DHE_DSS_WITH_RC4_128_SHA: \
        case TLS_DH_anon_WITH_AES_128_CBC_SHA256: \
        case TLS_DH_anon_WITH_AES_256_CBC_SHA256: \
        case TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA: \
        case TLS_DH_anon_WITH_SEED_CBC_SHA: \
        case TLS_DH_anon_WITH_AES_128_GCM_SHA256: \
        case TLS_DH_anon_WITH_AES_256_GCM_SHA384: \
        case TLS_PSK_WITH_NULL_SHA256: \
        case TLS_PSK_WITH_NULL_SHA384: \
        case TLS_DHE_PSK_WITH_NULL_SHA256: \
        case TLS_DHE_PSK_WITH_NULL_SHA384: \
        case TLS_RSA_PSK_WITH_NULL_SHA256: \
        case TLS_RSA_PSK_WITH_NULL_SHA384: \
        case TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256: \
        case TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256: \
        case TLS_DES_64_CBC_WITH_SHA: \
        case TLS_DES_64_CFB64_WITH_MD5_1: \
        case TLS_ECDH_ECDSA_WITH_NULL_SHA: \
        case TLS_ECDH_ECDSA_WITH_RC4_128_SHA: \
        case TLS_ECDHE_ECDSA_WITH_NULL_SHA: \
        case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: \
        case TLS_ECDH_RSA_WITH_NULL_SHA: \
        case TLS_ECDH_RSA_WITH_RC4_128_SHA: \
        case TLS_ECDHE_RSA_WITH_NULL_SHA: \
        case TLS_ECDHE_RSA_WITH_RC4_128_SHA: \
        case TLS_ECDH_anon_WITH_NULL_SHA: \
        case TLS_ECDH_anon_WITH_RC4_128_SHA: \
        case TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA: \
        case TLS_ECDH_anon_WITH_AES_128_CBC_SHA: \
        case TLS_ECDH_anon_WITH_AES_256_CBC_SHA: \
        case TLS_ECDHE_PSK_WITH_NULL_SHA: \
        case TLS_ECDHE_PSK_WITH_NULL_SHA256: \
        case TLS_ECDHE_PSK_WITH_NULL_SHA384: \
        case TLS_DH_anon_WITH_ARIA_128_GCM_SHA256: \
        case TLS_DH_anon_WITH_ARIA_256_GCM_SHA384: \
        case TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256: \
        case TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384: \
        case TLS_RSA_FIPS_WITH_DES_CBC_SHA_1: \
        case TLS_RSA_FIPS_WITH_DES_CBC_SHA_2: \
            ssl->stat |= SSL_STAT_WEAK_CIPHER; \
            break; \
        default: \
            break; \
    }

#endif // __SSL_CIPHER_H__
