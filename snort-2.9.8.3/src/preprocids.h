/****************************************************************************
 *
 * Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef _PREPROC_IDS_H
#define _PREPROC_IDS_H

#include <stdint.h>

/*
**  Preprocessor Communication Defines
**  ----------------------------------
**  These defines allow preprocessors to be turned
**  on and off for each packet.  Preprocessors can be
**  turned off and on before preprocessing occurs and
**  during preprocessing.
**
**  Currently, the order in which the preprocessors are
**  placed in the snort.conf determine the order of
**  evaluation.  So if one module wants to turn off
**  another module, it must come first in the order.
*/

// currently 64 bits (preprocessors)
// are available.

#define PP_BO                      0
#define PP_APP_ID                  1
#define PP_DNS                     2
#define PP_FRAG3                   3
#define PP_FTPTELNET               4
#define PP_HTTPINSPECT             5
#define PP_PERFMONITOR             6
#define PP_RPCDECODE               7
#define PP_SHARED_RULES            8
#define PP_SFPORTSCAN              9
#define PP_SMTP                   10
#define PP_SSH                    11
#define PP_SSL                    12
#define PP_STREAM                 13
#define PP_TELNET                 14
#define PP_ARPSPOOF               15
#define PP_DCE2                   16
#define PP_SDF                    17
#define PP_NORMALIZE              18
#define PP_ISAKMP                 19  // used externally
#define PP_SESSION                20
#define PP_SIP                    21
#define PP_POP                    22
#define PP_IMAP                   23
#define PP_NETWORK_DISCOVERY      24  // used externally
#define PP_FW_RULE_ENGINE         25  // used externally
#define PP_REPUTATION             26
#define PP_GTP                    27
#define PP_MODBUS                 28
#define PP_DNP3                   29
#define PP_FILE                   30
#define PP_FILE_INSPECT           31
#define PP_NAP_RULE_ENGINE        32
#define PP_PREFILTER_RULE_ENGINE  33  // used externally
#define PP_MAX                    34

#define PP_ENABLE_ALL (~0)
#define PP_DISABLE_ALL 0x0

// preprocessors that run before or as part of Network Analysis Policy processing... If enabled by
// configuration they are never disabled
#define PP_CLASS_NETWORK ( ( UINT64_C(1) << PP_FRAG3 ) | ( UINT64_C(1) << PP_PERFMONITOR ) | \
                           ( UINT64_C(1) << PP_SFPORTSCAN ) | ( UINT64_C(1) << PP_STREAM ) | \
                           ( UINT64_C(1) << PP_NORMALIZE ) | ( UINT64_C(1) << PP_SESSION ) | \
                           ( UINT64_C(1) << PP_REPUTATION ) )

// Firewall and Application ID & Netowrk Discovery preprocessors...also always run if enabled by configuration
#define PP_CLASS_NGFW ( ( UINT64_C(1) << PP_APP_ID ) | ( UINT64_C(1) << PP_FW_RULE_ENGINE ) | \
                        ( UINT64_C(1) << PP_NETWORK_DISCOVERY ) | ( UINT64_C(1) << PP_PREFILTER_RULE_ENGINE ) )

// Application preprocessors...once the application or protocol for a stream is determined only preprocessors
// that analyze that type of stream are enabled (usually there is only 1...)
#define PP_CLASS_PROTO_APP ( ( UINT64_C(1) << PP_BO ) | ( UINT64_C(1) << PP_DNS ) | \
                             ( UINT64_C(1) << PP_FTPTELNET ) | ( UINT64_C(1) << PP_HTTPINSPECT ) | \
                             ( UINT64_C(1) << PP_RPCDECODE ) | ( UINT64_C(1) << PP_SHARED_RULES ) | \
                             ( UINT64_C(1) << PP_SMTP ) | ( UINT64_C(1) << PP_SSH ) | \
                             ( UINT64_C(1) << PP_SSL ) | ( UINT64_C(1) << PP_TELNET ) | \
                             ( UINT64_C(1) << PP_ARPSPOOF ) | ( UINT64_C(1) << PP_DCE2 ) | \
                             ( UINT64_C(1) << PP_SDF ) | ( UINT64_C(1) << PP_ISAKMP) | \
                             ( UINT64_C(1) << PP_POP ) | ( UINT64_C(1) << PP_IMAP ) | \
                             ( UINT64_C(1) << PP_GTP ) | ( UINT64_C(1) << PP_MODBUS ) | \
                             ( UINT64_C(1) << PP_DNP3 ) | ( UINT64_C(1) << PP_FILE ) | \
                             ( UINT64_C(1) << PP_FILE_INSPECT ) )

#define PP_DEFINED_GLOBAL ( ( UINT64_C(1) << PP_APP_ID ) | ( UINT64_C(1) << PP_FW_RULE_ENGINE ) | \
                            ( UINT64_C(1) << PP_NETWORK_DISCOVERY ) | ( UINT64_C(1) << PP_PERFMONITOR) | \
                            ( UINT64_C(1) << PP_SESSION ) | ( UINT64_C(1) << PP_PREFILTER_RULE_ENGINE ) )

#define PP_CORE_ORDER_SESSION   0
#define PP_CORE_ORDER_IPREP     1
#define PP_CORE_ORDER_NAP       2
#define PP_CORE_ORDER_NORML     3
#define PP_CORE_ORDER_FRAG3     4
#define PP_CORE_ORDER_PREFILTER 5   // used externally
#define PP_CORE_ORDER_STREAM    6

#define PRIORITY_CORE            0x0
#define PRIORITY_CORE_LAST      0x0f
#define PRIORITY_FIRST          0x10
#define PRIORITY_NETWORK        0x20
#define PRIORITY_TRANSPORT     0x100
#define PRIORITY_TUNNEL        0x105
#define PRIORITY_SCANNER       0x110
#define PRIORITY_APPLICATION   0x200
#define PRIORITY_LAST         0xffff

typedef uint64_t PreprocEnableMask;

#endif /* _PREPROC_IDS_H */

