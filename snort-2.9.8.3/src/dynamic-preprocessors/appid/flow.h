/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2005-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#ifndef _APPID_SESSION_H
#define _APPID_SESSION_H

#include <stdint.h>
#include <time.h>

#include "sf_snort_packet.h"
#include "flow_error.h"
#include "appId.h"
#include "appIdApi.h"
#include "service_state.h"
#include "lengthAppCache.h"
#include "thirdparty_appid_api.h"
#include "thirdparty_appid_types.h"
#include "sflsq.h"

#define SF_DEBUG_FILE   stdout
#define NUMBER_OF_PTYPES    9

#define APPID_SESSION_DATA_NONE                  0

#define APPID_SESSION_DATA_DHCP_FP_DATA          2
#define APPID_SESSION_DATA_SMB_DATA              4
#define APPID_SESSION_DATA_DHCP_INFO             5

#define APPID_SESSION_DATA_SERVICE_MODSTATE_BIT  0x20000000
#define APPID_SESSION_DATA_CLIENT_MODSTATE_BIT   0x40000000
#define APPID_SESSION_DATA_DETECTOR_MODSTATE_BIT 0x80000000

/* AppId Session internal flags */
typedef enum {
    APPID_SESSION_APP_REINSPECT         = (1 << 0),
    APPID_SESSION_RESPONSE_CODE_CHECKED = (1 << 1),
    APPID_SESSION_REXEC_STDERR          = (1 << 2),
    APPID_SESSION_CHP_INSPECTING        = (1 << 3),
    APPID_SESSION_STICKY_SERVICE        = (1 << 4),
    APPID_SESSION_APP_REINSPECT_SSL     = (1 << 5),
    APPID_SESSION_APP_NO_TPI            = (1 << 6),
} tFlowFlags;


#define APPID_SESSION_BIDIRECTIONAL_CHECKED  (APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED)
#define APPID_SESSION_DO_RNA (APPID_SESSION_RESPONDER_MONITORED | APPID_SESSION_INITIATOR_MONITORED | APPID_SESSION_DISCOVER_USER | APPID_SESSION_SPECIAL_MONITORED)
struct RNAServiceElement;

typedef enum
{
    RNA_STATE_NONE = 0,
    RNA_STATE_DIRECT,
    RNA_STATE_STATEFUL,
    RNA_STATE_FINISHED
} RNA_INSPECTION_STATE;
typedef void (*AppIdFreeFCN)(void *);

#define FINGERPRINT_UDP_FLAGS_XENIX 0x00000800
#define FINGERPRINT_UDP_FLAGS_NT    0x00001000
#define FINGERPRINT_UDP_FLAGS_MASK  (FINGERPRINT_UDP_FLAGS_XENIX | FINGERPRINT_UDP_FLAGS_NT)


typedef struct _AppIdFlowData
{
    struct _AppIdFlowData *next;
    unsigned fd_id;
    void *fd_data;
    AppIdFreeFCN fd_free;
} AppIdFlowData;

#define APPID_SESSION_TYPE_IGNORE   APPID_FLOW_TYPE_IGNORE
#define APPID_SESSION_TYPE_NORMAL   APPID_FLOW_TYPE_NORMAL
#define APPID_SESSION_TYPE_TMP      APPID_FLOW_TYPE_TMP

typedef struct _APPID_SESSION_STRUCT_FLAG
{
    APPID_FLOW_TYPE flow_type;
} APPID_SESSION_STRUCT_FLAG;

typedef struct _tCommonAppIdData
{
    APPID_SESSION_STRUCT_FLAG fsf_type;  /* This must be first. */
    unsigned policyId;
    //flags not seen by other preprocessors
    unsigned internalFlags;
    //flags shared with other preprocessor via session attributes.
    unsigned externalFlags;
    sfaddr_t initiator_ip;
    uint16_t initiator_port;
} tCommonAppIdData;

typedef struct _tTmpAppIdData
{
    tCommonAppIdData common;

    struct _tTmpAppIdData *next;
} tTmpAppIdData;

#define SCAN_HTTP_VIA_FLAG          (1<<0)
#define SCAN_HTTP_USER_AGENT_FLAG   (1<<1)
#define SCAN_HTTP_HOST_URL_FLAG     (1<<2)
#define SCAN_SSL_HOST_FLAG          (1<<4)
#define SCAN_HOST_PORT_FLAG         (1<<5)
#define SCAN_HTTP_VENDOR_FLAG       (1<<6)
#define SCAN_HTTP_XWORKINGWITH_FLAG (1<<7)
#define SCAN_HTTP_CONTENT_TYPE_FLAG (1<<8)

typedef struct _fflow_info
{
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol;
    tAppId appId;
    int flow_prepared;
} fflow_info;

typedef struct _httpSession
{
    char *host;
    char *url;
    char *uri;
    char *via;
    char *useragent;
    char *response_code;
    char *referer;
    char *cookie;
    char *content_type;
    char *location;
    char *body;
    char *req_body;
    char *server;
    char *x_working_with;
    char *new_url;
    char *new_cookie;

    uint16_t uriOffset;
    uint16_t uriEndOffset;
    uint16_t cookieOffset;
    uint16_t cookieEndOffset;

    fflow_info *fflow;

    int chp_finished;
    tAppId chp_candidate;
    tAppId chp_alt_candidate;
    int chp_hold_flow;
    int ptype_req_counts[NUMBER_OF_PTYPES];
    int total_found;
    unsigned app_type_flags;
    int num_matches;
    int num_scans;
    int get_offsets_from_rebuilt;
    SEARCH_SUPPORT_TYPE search_support_type;
    bool skip_simple_detect;    // Flag to indicate if simple detection of client ID, payload ID, etc
                                // should be skipped

#if RESPONSE_CODE_PACKET_THRESHHOLD
    unsigned response_code_packets;
#endif

} httpSession;

// For dnsSession.state:
#define DNS_GOT_QUERY    0x01
#define DNS_GOT_RESPONSE 0x02

typedef struct _dnsSession
{
    uint8_t   state;            // state
    uint8_t   host_len;         // for host
    uint8_t   response_type;    // response: RCODE
    uint16_t  id;               // DNS msg ID
    uint16_t  host_offset;      // for host
    uint16_t  record_type;      // query: QTYPE
    uint32_t  ttl;              // response: TTL
    char     *host;             // host (usually query, but could be response for reverse lookup)
} dnsSession;

struct _RNAServiceSubtype;

typedef struct _tlsSession
{
    char *tls_host;
    int   tls_host_strlen;
    char *tls_cname;
    int   tls_cname_strlen;
    char *tls_orgUnit;
    int   tls_orgUnit_strlen;
} tlsSession;

typedef struct AppIdData
{
    tCommonAppIdData common;

    struct AppIdData *next;

    void *ssn;
    sfaddr_t service_ip;
    uint16_t service_port;
    uint8_t proto;
    uint8_t previous_tcp_flags;

    AppIdFlowData *flowData;

    /**AppId matching service side */
    tAppId serviceAppId;
    tAppId portServiceAppId;
    /**RNAServiceElement for identifying detector*/
    const struct RNAServiceElement *serviceData;
    RNA_INSPECTION_STATE rnaServiceState;
    char *serviceVendor;
    char *serviceVersion;
    struct _RNAServiceSubtype *subtype;
    AppIdServiceIDState *id_state;
    char *netbios_name;
    SF_LIST * candidate_service_list;
    unsigned int num_candidate_services_tried;
    int got_incompatible_services;

    /**AppId matching client side */
    tAppId clientAppId;
    tAppId clientServiceAppId;
    char *clientVersion;
    /**RNAClientAppModule for identifying client detector*/
    const struct RNAClientAppModule *clientData;
    RNA_INSPECTION_STATE rnaClientState;
    SF_LIST * candidate_client_list;
    unsigned int num_candidate_clients_tried;
    bool tried_reverse_service;

    /**AppId matching payload*/
    tAppId payloadAppId;
    tAppId referredPayloadAppId;
    tAppId miscAppId;

    //appId determined by 3rd party library
    tAppId tpAppId;
    tAppId tpPayloadAppId;

    char *username;
    tAppId usernameService;

    char *netbiosDomain;

    uint32_t flowId;

    httpSession *hsession;
    tlsSession  *tsession;

#if 0
    char *host;
    char *url;
    char *via;
    char *useragent;
    char *response_code;
    char *referer;
#endif
    unsigned scan_flags;
#if RESPONSE_CODE_PACKET_THRESHHOLD
    unsigned response_code_packets;
#endif

    tAppId referredAppId;

    tAppId tmpAppId;
    void *tpsession;
    uint16_t init_tpPackets;
    uint16_t resp_tpPackets;
    uint8_t tpReinspectByInitiator;
    char *payloadVersion;

    uint16_t session_packet_count;
    int16_t snortId;

    /* Length-based detectors. */
    tLengthKey length_sequence;

    struct
    {
        uint32_t    firstPktsecond;
        uint32_t    lastPktsecond;
        uint64_t    initiatorBytes;
        uint64_t    responderBytes;
    } stats;

    /* Policy and rule ID for related flows (e.g. ftp-data) */
    struct AppIdData *expectedFlow;
    //struct FwEarlyData *fwData;

    //appIds picked from encrypted session.
    struct {
        tAppId serviceAppId;
        tAppId clientAppId;
        tAppId payloadAppId;
        tAppId miscAppId;
        tAppId referredAppId;
    } encrypted;
    // New fields introduced for DNS Blacklisting
    dnsSession *dsession;
    /*
    char *dns_query;
    int  dns_query_len ;
    uint16_t dns_record_type;
    uint16_t dns_response_type;
    uint16_t dns_ttl;
    char *dns_resp_page ;
    */
    void * firewallEarlyData;
    tAppId pastIndicator;
    tAppId pastForecast;
} tAppIdData;
/**
 * Mark a flow with a particular flag
 *
 * @param flow
 * @param flags
 */
static inline void setAppIdIntFlag(tAppIdData *flow, unsigned flags)
{
    flow->common.internalFlags |= flags;
}
static inline void setAppIdExtFlag(tAppIdData *flow, unsigned flags)
{
    flow->common.externalFlags |= flags;
}

/**
 * Mark a flow with a particular flag
 *
 * @param flow
 * @param flags
 */
static inline void clearAppIdIntFlag(tAppIdData *flow, unsigned flags)
{
    flow->common.internalFlags &= ~flags;
}
static inline void clearAppIdExtFlag(tAppIdData *flow, unsigned flags)
{
    flow->common.externalFlags &= ~flags;
}

/**
 * Check to see if a particular flag exists
 *
 * @param flow
 * @param flags
 */
static inline unsigned getAppIdIntFlag(tAppIdData *flow, unsigned flags)
{
    return (flow->common.internalFlags & flags);
}
static inline unsigned getAppIdExtFlag(tAppIdData *flow, unsigned flags)
{
    return (flow->common.externalFlags & flags);
}

void AppIdFlowdataFree(tAppIdData *flowp);
void AppIdFlowdataFini(void);
void *AppIdFlowdataGet(tAppIdData *flowp, unsigned id);
int AppIdFlowdataAdd(tAppIdData *flowp, void *data, unsigned id, AppIdFreeFCN fcn);
void *AppIdFlowdataRemove(tAppIdData *flowp, unsigned id);
void AppIdFlowdataDelete(tAppIdData *flowp, unsigned id);
void AppIdFlowdataDeleteAllByMask(tAppIdData *flowp, unsigned mask);
tAppIdData *AppIdEarlySessionCreate(tAppIdData *flowp, SFSnortPacket *ctrlPkt, sfaddr_t *cliIp, uint16_t cliPort,
                          sfaddr_t *srvIp, uint16_t srvPort, uint8_t proto, int16_t app_id, int flags);
struct RNAServiceElement;
int AppIdFlowdataAddId(tAppIdData *flowp, uint16_t port, const struct RNAServiceElement *svc_element);

#endif /* _APPID_SESSION_H */

