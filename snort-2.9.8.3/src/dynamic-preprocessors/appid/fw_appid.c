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

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <syslog.h>
#ifndef WIN32
#include <strings.h>
#include <sys/time.h>
#endif
#include <pthread.h>
#include "appIdApi.h"
#include "fw_appid.h"
#include "profiler.h"
#include "client_app_base.h"
#include "httpCommon.h"
#include "luaDetectorApi.h"
#include "http_url_patterns.h"
#include "fw_appid.h"
#include "detector_http.h"
#include "service_ssl.h"
#include "detector_dns.h"
#include "flow.h"
#include "common_util.h"
#include "spp_appid.h"
#include "hostPortAppCache.h"
#include "lengthAppCache.h"
#include "appInfoTable.h"
#include "appIdStats.h"
#include "sf_mlmp.h"
#include "ip_funcs.h"
#include "app_forecast.h"
#include "thirdparty_appid_types.h"
#include "thirdparty_appid_utils.h"
#include "appInfoTable.h"
#include "service_base.h"

//#define DEBUG_APP_ID_SESSIONS   1
//#define DEBUG_FW_APPID  1
#define DEBUG_FW_APPID_PORT 80

#define MAX_ATTR_LEN           1024
#define GENERIC_APP_OFFSET 2000000000
#define HTTP_PREFIX "http://"

#define APP_MAPPING_FILE "appMapping.data"

#ifdef RNA_DEBUG_PE
static const char *MODULE_NAME = "fw_appid";
#endif

static volatile int app_id_debug_flag;
static FWDebugSessionConstraints app_id_debug_info;
char app_id_debug_session[FW_DEBUG_SESSION_ID_SIZE];
bool app_id_debug_session_flag;

#ifdef PERF_PROFILING
PreprocStats tpPerfStats;
PreprocStats tpLibPerfStats;
PreprocStats httpPerfStats;
PreprocStats clientMatchPerfStats;
PreprocStats serviceMatchPerfStats;
#endif

#define HTTP_PATTERN_MAX_LEN    1024
#define PORT_MAX 65535

unsigned long app_id_raw_packet_count = 0;
unsigned long app_id_processed_packet_count = 0;
unsigned long app_id_ignored_packet_count = 0;
static tAppIdData *app_id_free_list;
static tTmpAppIdData *tmp_app_id_free_list;
int app_id_debug;
static int ptype_scan_counts[NUMBER_OF_PTYPES];

static void ProcessThirdPartyResults(tAppIdData* appIdSession, int confidence, tAppId* proto_list, ThirdPartyAppIDAttributeData* attribute_data);
static void ExamineRtmpMetadata(tAppIdData *appIdSession);

static inline void appSharedDataFree(tAppIdData * sharedData)
{
    sharedData->next = app_id_free_list;
    app_id_free_list = sharedData;
}

static inline void appTmpSharedDataFree(tTmpAppIdData * sharedData)
{
    sharedData->next = tmp_app_id_free_list;
    tmp_app_id_free_list = sharedData;
}

static inline void appHttpFieldClear (httpSession *hsession)
{
    if (hsession == NULL) return;

    if (hsession->referer)
    {
        free(hsession->referer);
        hsession->referer = NULL;
    }
    if (hsession->cookie)
    {
        free(hsession->cookie);
        hsession->cookie = NULL;
    }
    if (hsession->url)
    {
        free(hsession->url);
        hsession->url = NULL;
    }
    if (hsession->useragent)
    {
        free(hsession->useragent);
        hsession->useragent = NULL;
    }
    if (hsession->host)
    {
        free(hsession->host);
        hsession->host = NULL;
    }
    if (hsession->uri)
    {
        free(hsession->uri);
        hsession->uri = NULL;
    }
    if (hsession->content_type)
    {
        free(hsession->content_type);
        hsession->content_type = NULL;
    }
    if (hsession->location)
    {
        free(hsession->location);
        hsession->location = NULL;
    }
    if (hsession->body)
    {
        free(hsession->body);
        hsession->body = NULL;
    }
    if (hsession->req_body)
    {
        free(hsession->req_body);
        hsession->req_body = NULL;
    }
}

static inline void appHttpSessionDataFree (httpSession *hsession)
{
    if (hsession == NULL) return;

    appHttpFieldClear(hsession);

    if (hsession->new_url)
    {
        free(hsession->new_url);
        hsession->new_url = NULL;
    }
    if (hsession->new_cookie)
    {
        free(hsession->new_cookie);
        hsession->new_cookie = NULL;
    }
    if (hsession->fflow)
    {
        free(hsession->fflow);
        hsession->fflow = NULL;
    }
    if (hsession->via)
    {
        free(hsession->via);
        hsession->via = NULL;
    }
    if (hsession->content_type)
    {
        free(hsession->content_type);
        hsession->content_type = NULL;
    }
    if (hsession->response_code)
    {
        free(hsession->response_code);
        hsession->response_code = NULL;
    }

    free(hsession);
}

static inline void appDNSSessionDataFree(dnsSession *dsession)
{
    if (dsession == NULL) return;
    if (dsession->host)
    {
        free(dsession->host);
        dsession->host = NULL;
    }
    free(dsession);
}

static inline void appTlsSessionDataFree (tlsSession *tsession)
{
    if (tsession == NULL) return;

    if (tsession->tls_host)
        free(tsession->tls_host);
    if (tsession->tls_cname)
        free(tsession->tls_cname);
    if (tsession->tls_orgUnit)
        free(tsession->tls_orgUnit);
    free(tsession);
}

void appSharedDataDelete(tAppIdData * sharedData)
{
    RNAServiceSubtype *subtype;

    if (sharedData)
    {
#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
        if (sharedData->service_port == DEBUG_FW_APPID_PORT)
#endif
            fprintf(SF_DEBUG_FILE, "Deleting session %p\n", sharedData);
#endif
        /*check daq flag */
        appIdStatsUpdate(sharedData);

        if (sharedData->ssn)
            FailInProcessService(sharedData, pAppidActiveConfig);
        AppIdFlowdataFree(sharedData);

        if (thirdparty_appid_module)
        {
            thirdparty_appid_module->session_delete(sharedData->tpsession, 0);    // we're completely done with it
            sharedData->tpsession = NULL;
        }
        free(sharedData->clientVersion);
        free(sharedData->serviceVendor);
        free(sharedData->serviceVersion);
        free(sharedData->netbios_name);
        while ((subtype = sharedData->subtype))
        {
            sharedData->subtype = subtype->next;
            free(*(void **)&subtype->service);
            free(*(void **)&subtype->vendor);
            free(*(void **)&subtype->version);
            free(subtype);
        }
        if (sharedData->candidate_service_list != NULL)
        {
            sflist_free(sharedData->candidate_service_list);
            sharedData->candidate_service_list = NULL;
        }
        if (sharedData->candidate_client_list != NULL)
        {
            sflist_free(sharedData->candidate_client_list);
            sharedData->candidate_client_list = NULL;
        }
        free(sharedData->username);
        free(sharedData->netbiosDomain);
        free(sharedData->payloadVersion);
        appHttpSessionDataFree(sharedData->hsession);
        appTlsSessionDataFree(sharedData->tsession);
        appDNSSessionDataFree(sharedData->dsession);
        sharedData->tsession = NULL;

        free(sharedData->firewallEarlyData);
        sharedData->firewallEarlyData = NULL;

        appSharedDataFree(sharedData);
    }
}
/* The UNSYNCED_SNORT_ID value is to cheaply insure we get
   the value from snort rather than assume */
#define UNSYNCED_SNORT_ID   0x5555

tAppIdData* appSharedDataAlloc(uint8_t proto, sfaddr_t *ip)
{
    static uint32_t gFlowId;
    tAppIdData *data;

    if (app_id_free_list)
    {
        data = app_id_free_list;
        app_id_free_list = data->next;
        memset(data, 0, sizeof(*data));
    }
    else if (!(data = calloc(1, sizeof(*data))))
        DynamicPreprocessorFatalMessage("Could not allocate tAppIdData data");

    if (thirdparty_appid_module)
        if (!(data->tpsession = thirdparty_appid_module->session_create()))
            DynamicPreprocessorFatalMessage("Could not allocate tAppIdData->tpsession data");

    data->flowId = ++gFlowId;
    data->common.fsf_type.flow_type = APPID_SESSION_TYPE_NORMAL;
    data->proto = proto;
    data->common.initiator_ip = *ip;
    data->snortId = UNSYNCED_SNORT_ID;
    return data;
}

static inline tAppIdData* appSharedCreateData(const SFSnortPacket *p, uint8_t proto, int direction)
{
#ifdef DEBUG_FW_APPID
    static unsigned long packet_count;
#endif
    tAppIdData *data;
    sfaddr_t *ip;

    ip = (direction == APP_ID_FROM_INITIATOR) ? GET_SRC_IP(p) : GET_DST_IP(p);
    data = appSharedDataAlloc(proto, ip);

    if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && p->src_port != p->dst_port)
        data->common.initiator_port = (direction == APP_ID_FROM_INITIATOR) ? p->src_port : p->dst_port;
    data->ssn = p->stream_session;
#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
        if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
            fprintf(SF_DEBUG_FILE, "pkt %lu : tAppIdData: Allocated %p\n", ++packet_count, data);
#endif
    data->stats.firstPktsecond = p->pkt_header->ts.tv_sec;

    _dpd.sessionAPI->set_application_data(p->stream_session, PP_APP_ID, data,
            (void (*)(void *))appSharedDataDelete);
    return data;
}

static inline void appSharedReInitData(tAppIdData* session)
{
    session->miscAppId = APP_ID_NONE;

    //payload
    if (isSslServiceAppId(session->tpAppId))
    {
        session->payloadAppId = session->referredPayloadAppId = session->tpPayloadAppId =  APP_ID_NONE;
        clearAppIdExtFlag(session, APPID_SESSION_CONTINUE);
        if (session->payloadVersion)
        {
            free(session->payloadVersion);
            session->payloadVersion = NULL;
        }
        if (session->hsession && session->hsession->url)
        {
            free(session->hsession->url);
            session->hsession->url = NULL;
        }
    }

    //service
    if (!getAppIdIntFlag(session, APPID_SESSION_STICKY_SERVICE))
    {
        clearAppIdIntFlag(session, APPID_SESSION_STICKY_SERVICE);

        session->tpAppId = session->serviceAppId = session->portServiceAppId = APP_ID_NONE;
        if (session->serviceVendor)
        {
            free(session->serviceVendor);
            session->serviceVendor = NULL;
        }
        if (session->serviceVersion)
        {
            free(session->serviceVersion);
            session->serviceVersion = NULL;
        }

        IP_CLEAR(session->service_ip);
        session->service_port = 0;
        session->rnaServiceState = RNA_STATE_NONE;
        session->serviceData = NULL;
        AppIdFlowdataDeleteAllByMask(session, APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);
    }

    //client
    session->clientAppId = session->clientServiceAppId = APP_ID_NONE;
    if (session->clientVersion)
    {
        free(session->clientVersion);
        session->clientVersion = NULL;
    }
    session->rnaClientState = RNA_STATE_NONE;
    AppIdFlowdataDeleteAllByMask(session, APPID_SESSION_DATA_CLIENT_MODSTATE_BIT);

    //3rd party cleaning
    if (thirdparty_appid_module)
        thirdparty_appid_module->session_delete(session->tpsession, 1);
    session->init_tpPackets = 0;
    session->resp_tpPackets = 0;

    session->scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
    clearAppIdExtFlag(session, APPID_SESSION_SERVICE_DETECTED|APPID_SESSION_CLIENT_DETECTED|APPID_SESSION_SSL_SESSION|APPID_SESSION_HTTP_SESSION);
    clearAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT);
}
void fwAppIdFini(tAppIdConfig *pConfig)
{
#ifdef RNA_FULL_CLEANUP
    tAppIdData *app_id;
    tTmpAppIdData *tmp_app_id;

    while ((app_id = app_id_free_list))
    {
        app_id_free_list = app_id->next;
        free(app_id);
    }

    while ((tmp_app_id = tmp_app_id_free_list))
    {
        tmp_app_id_free_list = tmp_app_id->next;
        free(tmp_app_id);
    }
    AppIdFlowdataFini();
#endif

    appInfoTableFini(pConfig);
}

static inline int PENetworkMatch(const sfaddr_t *pktAddr, const PortExclusion *pe)
{
    const uint32_t* pkt = sfaddr_get_ip6_ptr(pktAddr);
    const uint32_t* nm = pe->netmask.s6_addr32;
    const uint32_t* peIP = pe->ip.s6_addr32;
    return (((pkt[0] & nm[0]) == peIP[0])
            && ((pkt[1] & nm[1]) == peIP[1])
            && ((pkt[2] & nm[2]) == peIP[2])
            && ((pkt[3] & nm[3]) == peIP[3]));
}

static inline int checkPortExclusion(const SFSnortPacket *pkt, int reversed)
{
    SF_LIST * *src_port_exclusions;
    SF_LIST * *dst_port_exclusions;
    SF_LIST *pe_list;
    PortExclusion *pe;
    sfaddr_t *s_ip;
    uint16_t port;
    tAppIdConfig *pConfig = appIdActiveConfigGet();

    if (IsTCP(pkt))
    {
        src_port_exclusions = pConfig->tcp_port_exclusions_src;
        dst_port_exclusions = pConfig->tcp_port_exclusions_dst;
    }
    else if (IsUDP(pkt))
    {
        src_port_exclusions = pConfig->udp_port_exclusions_src;
        dst_port_exclusions = pConfig->udp_port_exclusions_dst;
    }
    else
        return 0;

    /* check the source port */
    port = reversed ? pkt->dst_port : pkt->src_port;
    if( port && (pe_list=src_port_exclusions[port]) != NULL )
    {
        s_ip = reversed ? GET_DST_IP(pkt) : GET_SRC_IP(pkt);

        /* walk through the list of port exclusions for this port */
        for (pe=(PortExclusion *)sflist_first(pe_list);
                pe;
                pe=(PortExclusion *)sflist_next(pe_list))
        {
            if( PENetworkMatch(s_ip, pe))
            {
#ifdef RNA_DEBUG_PE
                char inetBuffer[INET6_ADDRSTRLEN];
                inetBuffer[0] = 0;
                inet_ntop(sfaddr_family(s_ip), (void *)sfaddr_get_ptr(s_ip), inetBuffer, sizeof(inetBuffer));

                SFDEBUG(MODULE_NAME, "excluding src port: %d",port);
                SFDEBUG(MODULE_NAME, "for addresses src: %s", inetBuffer);
#endif
                return 1;
            }
        }
    }

    /* check the dest port */
    port = reversed ? pkt->src_port : pkt->dst_port;
    if( port && (pe_list=dst_port_exclusions[port]) != NULL )
    {
        s_ip = reversed ? GET_SRC_IP(pkt) : GET_DST_IP(pkt);

        /* walk through the list of port exclusions for this port */
        for (pe=(PortExclusion *)sflist_first(pe_list);
                pe;
                pe=(PortExclusion *)sflist_next(pe_list))
        {
            if( PENetworkMatch(s_ip, pe))
            {
#ifdef RNA_DEBUG_PE
                char inetBuffer[INET6_ADDRSTRLEN];
                inetBuffer[0] = 0;
                inet_ntop(sfaddr_family(s_ip), (void *)sfaddr_get_ptr(s_ip), inetBuffer, sizeof(inetBuffer));
                SFDEBUG(MODULE_NAME, "excluding dst port: %d",port);
                SFDEBUG(MODULE_NAME, "for addresses dst: %s", inetBuffer);
#endif
                return 1;
            }
        }
    }

    return 0;
}

static inline bool fwAppIdDebugCheck(void *lwssn, tAppIdData *session, volatile int debug_flag,
        FWDebugSessionConstraints *info, char *debug_session, int direction)
{
    if (debug_flag)
    {
        const StreamSessionKey *key;

        key = _dpd.sessionAPI->get_key_from_session_ptr(lwssn);
        if ((!info->protocol || info->protocol == key->protocol) &&
            (((!info->sport || info->sport == key->port_l) &&
              (!info->sip_flag || memcmp(&info->sip, key->ip_l, sizeof(info->sip)) == 0) &&
              (!info->dport || info->dport == key->port_h) &&
              (!info->dip_flag || memcmp(&info->dip, key->ip_h, sizeof(info->dip)) == 0)) ||
             ((!info->sport || info->sport == key->port_h) &&
               (!info->sip_flag || memcmp(&info->sip, key->ip_h, sizeof(info->sip)) == 0) &&
               (!info->dport || info->dport == key->port_l) &&
               (!info->dip_flag || memcmp(&info->dip, key->ip_l, sizeof(info->dip)) == 0))))
        {
            int af;
            const struct in6_addr* sip;
            const struct in6_addr* dip;
            unsigned offset;
            uint16_t sport;
            uint16_t dport;
            char sipstr[INET6_ADDRSTRLEN];
            char dipstr[INET6_ADDRSTRLEN];
            if (session && session->common.fsf_type.flow_type != APPID_SESSION_TYPE_IGNORE)
            {
                if (session->common.initiator_port)
                {
                    if (session->common.initiator_port == key->port_l)
                    {
                        sip = (const struct in6_addr*)key->ip_l;
                        dip = (const struct in6_addr*)key->ip_h;
                        sport = key->port_l;
                        dport = key->port_h;
                    }
                    else
                    {
                        sip = (const struct in6_addr*)key->ip_h;
                        dip = (const struct in6_addr*)key->ip_l;
                        sport = key->port_h;
                        dport = key->port_l;
                    }
                }
                else if (sfip_fast_eq6((sfaddr_t*)&session->common.initiator_ip, (sfaddr_t*)key->ip_l) == 0)
                {
                    sip = (const struct in6_addr*)key->ip_l;
                    dip = (const struct in6_addr*)key->ip_h;
                    sport = key->port_l;
                    dport = key->port_h;
                }
                else
                {
                    sip = (const struct in6_addr*)key->ip_h;
                    dip = (const struct in6_addr*)key->ip_l;
                    sport = key->port_h;
                    dport = key->port_l;
                }
            }
            else
            {
                sip = (const struct in6_addr*)key->ip_l;
                dip = (const struct in6_addr*)key->ip_h;
                sport = key->port_l;
                dport = key->port_h;
            }
            sipstr[0] = 0;
            if (sip->s6_addr32[0] || sip->s6_addr32[1] || sip->s6_addr16[4] || (sip->s6_addr16[5] && sip->s6_addr16[5] != 0xFFFF))
            {
                af = AF_INET6;
                offset = 0;
            }
            else
            {
                af = AF_INET;
                offset = 12;
            }
            inet_ntop(af, &sip->s6_addr[offset], sipstr, sizeof(sipstr));
            dipstr[0] = 0;
            if (dip->s6_addr32[0] || dip->s6_addr32[1] || dip->s6_addr16[4] || (dip->s6_addr16[5] && dip->s6_addr16[5] != 0xFFFF))
            {
                af = AF_INET6;
                offset = 0;
            }
            else
            {
                af = AF_INET;
                offset = 12;
            }
            inet_ntop(af, &dip->s6_addr[offset], dipstr, sizeof(dipstr));
            snprintf(debug_session, FW_DEBUG_SESSION_ID_SIZE, "%s-%u and %s-%u %u%s",
                    sipstr, (unsigned)sport, dipstr, (unsigned)dport, (unsigned)key->protocol,
                    (direction == APP_ID_FROM_INITIATOR) ? "":" R");
            return true;
        }
    }
    return false;
}

static inline void appIdDebugParse(const char *desc, const uint8_t *data, uint32_t length,
                          volatile int *debug_flag, FWDebugSessionConstraints *info)
{
    *debug_flag = 0;
    memset(info, 0, sizeof(*info));
    do
    {
        if (length >= sizeof(info->protocol))
        {
            info->protocol = *data;
            length -= sizeof(info->protocol);
            data += sizeof(info->protocol);
        }
        else
            break;

        if (length >= sizeof(info->sip))
        {

            memcpy(&info->sip, data, sizeof(info->sip));
            if (info->sip.s6_addr32[1] || info->sip.s6_addr32[2] || info->sip.s6_addr32[3])
                info->sip_flag = 1;
            else if (info->sip.s6_addr32[0])
            {
                info->sip.s6_addr32[3] = info->sip.s6_addr32[0];
                info->sip.s6_addr32[0] = 0;
                info->sip.s6_addr16[5] = 0xFFFF;
                info->sip_flag = 1;
            }
            length -= sizeof(info->sip);
            data += sizeof(info->sip);
        }
        else
            break;

        if (length >= sizeof(info->sport))
        {
            memcpy(&info->sport, data, sizeof(info->sport));
            length -= sizeof(info->sport);
            data += sizeof(info->sport);
        }
        else
            break;

        if (length >= sizeof(info->dip))
        {
            memcpy(&info->dip, data, sizeof(info->dip));
            if (info->dip.s6_addr32[1] || info->dip.s6_addr32[2] || info->dip.s6_addr32[3])
                info->dip_flag = 1;
            else if (info->dip.s6_addr32[0])
            {
                info->dip.s6_addr32[3] = info->dip.s6_addr32[0];
                info->dip.s6_addr32[0] = 0;
                info->dip.s6_addr16[5] = 0xFFFF;
                info->dip_flag = 1;
            }
            length -= sizeof(info->dip);
            data += sizeof(info->dip);
        }
        else
            break;

        if (length >= sizeof(info->dport))
        {
            memcpy(&info->dport, data, sizeof(info->dport));
            length -= sizeof(info->dport);
            data += sizeof(info->dport);
        }
        else
            break;
    } while (0);

    if (info->protocol || info->sip_flag || info->sport || info->dip_flag || info->dport)
    {
        int saf;
        int daf;
        char sipstr[INET6_ADDRSTRLEN];
        char dipstr[INET6_ADDRSTRLEN];

        if (!info->sip.s6_addr32[0] && !info->sip.s6_addr32[0] && !info->sip.s6_addr16[4] &&
            info->sip.s6_addr16[5] == 0xFFFF)
        {
            saf = AF_INET;
        }
        else
            saf = AF_INET6;
        if (!info->dip.s6_addr32[0] && !info->dip.s6_addr32[0] && !info->dip.s6_addr16[4] &&
            info->dip.s6_addr16[5] == 0xFFFF)
        {
            daf = AF_INET;
        }
        else
            daf = AF_INET6;
        if (!info->sip_flag)
            saf = daf;
        if (!info->dip_flag)
            daf = saf;
        sipstr[0] = 0;
        inet_ntop(saf, saf == AF_INET ? &info->sip.s6_addr32[3] : info->sip.s6_addr32, sipstr, sizeof(sipstr));
        dipstr[0] = 0;
        inet_ntop(daf, daf == AF_INET ? &info->dip.s6_addr32[3] : info->dip.s6_addr32, dipstr, sizeof(dipstr));
        _dpd.logMsg("Debugging %s with %s-%u and %s-%u %u\n", desc,
                    sipstr, (unsigned)info->sport,
                    dipstr, (unsigned)info->dport,
                    (unsigned)info->protocol);
        *debug_flag = 1;
    }
    else
        _dpd.logMsg("Debugging %s disabled\n", desc);
}
int AppIdDebug(uint16_t type, const uint8_t *data, uint32_t length, void **new_context,
               char* statusBuf, int statusBuf_len)
{
    appIdDebugParse("appId", data, length, &app_id_debug_flag, &app_id_debug_info);
    return 0;
}

unsigned isIPv4HostMonitored(uint32_t ip4, int32_t zone)
{
    NetworkSet *net_list;
    unsigned flags;
    tAppIdConfig *pConfig = appIdActiveConfigGet();

    if (zone >= 0 && zone < MAX_ZONES && pConfig->net_list_by_zone[zone])
        net_list = pConfig->net_list_by_zone[zone];
    else
        net_list = pConfig->net_list;

    NetworkSet_ContainsEx(net_list, ip4, &flags);
    return flags;
}

static inline unsigned isIPMonitored(const SFSnortPacket *p, int dst)
{
    uint32_t ipAddr;
    sfaddr_t *sf_ip;
    struct in_addr ip;
    NetworkSet *net_list;
    unsigned flags;
    int32_t zone;
    NSIPv6Addr ip6;
    tAppIdConfig *pConfig = appIdActiveConfigGet();

    if (!dst)
    {
        zone = p->pkt_header->ingress_group;
        sf_ip = GET_SRC_IP(p);
    }
    else
    {
        zone = (p->pkt_header->egress_index == DAQ_PKTHDR_UNKNOWN) ? p->pkt_header->ingress_group : p->pkt_header->egress_group;
        if (zone == DAQ_PKTHDR_FLOOD)
            return 0;
        sf_ip = GET_DST_IP(p);
    }
    if (zone >= 0 && zone < MAX_ZONES && pConfig->net_list_by_zone[zone])
        net_list = pConfig->net_list_by_zone[zone];
    else
        net_list = pConfig->net_list;
    if (sfaddr_family(sf_ip) == AF_INET)
    {
        ip.s_addr = sfaddr_get_ip4_value(sf_ip);
        if (ip.s_addr == 0xFFFFFFFF)
            return IPFUNCS_CHECKED;
        ipAddr = ntohl(ip.s_addr);
        NetworkSet_ContainsEx(net_list, ipAddr, &flags);
    }
    else
    {
        memcpy(&ip6, sfaddr_get_ptr(sf_ip), sizeof(ip6));
        NSIPv6AddrNtoH(&ip6);
        NetworkSet_Contains6Ex(net_list, &ip6, &flags);
    }
    return flags | IPFUNCS_CHECKED;
}

static inline int isSpecialSessionMonitored(const SFSnortPacket *p)
{
    sfaddr_t *srcAddr;

    srcAddr = GET_SRC_IP(p);
    if (sfaddr_family(srcAddr) == AF_INET)
    {
        if (IsUDP(p) && ((p->src_port == 68 && p->dst_port == 67) || (p->src_port == 67 && p->dst_port == 68)))
        {
            return 1;
        }
    }
    return 0;
}
static inline unsigned isSessionMonitored(const SFSnortPacket *p, int dir, tAppIdData *session)
{
    unsigned flags;
    unsigned flow_flags = _dpd.isAppIdRequired() ? APPID_SESSION_DISCOVER_APP : 0;

    flow_flags |= (dir == APP_ID_FROM_INITIATOR) ? APPID_SESSION_INITIATOR_SEEN : APPID_SESSION_RESPONDER_SEEN;
    if (session)
    {
        flow_flags |= session->common.externalFlags;
        if (session->common.policyId != appIdPolicyId)
        {
            if (checkPortExclusion(p, dir == APP_ID_FROM_RESPONDER))
            {
                flow_flags |= APPID_SESSION_INITIATOR_SEEN | APPID_SESSION_RESPONDER_SEEN | APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
                flow_flags &= ~(APPID_SESSION_INITIATOR_MONITORED | APPID_SESSION_RESPONDER_MONITORED);
                return flow_flags;
            }
            if (dir == APP_ID_FROM_INITIATOR)
            {
                if (getAppIdExtFlag(session, APPID_SESSION_INITIATOR_CHECKED))
                {
                    flags = isIPMonitored(p, 0);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_INITIATOR_MONITORED;
                }

                if (getAppIdExtFlag(session, APPID_SESSION_RESPONDER_CHECKED))
                {
                    flags = isIPMonitored(p, 1);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_RESPONDER_MONITORED;
                }
            }
            else
            {
                if (getAppIdExtFlag(session, APPID_SESSION_RESPONDER_CHECKED))
                {
                    flags = isIPMonitored(p, 0);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_RESPONDER_MONITORED;
                }

                if (getAppIdExtFlag(session, APPID_SESSION_INITIATOR_CHECKED))
                {
                    flags = isIPMonitored(p, 1);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_INITIATOR_MONITORED;
                }
            }
        }

        if (getAppIdExtFlag(session, APPID_SESSION_BIDIRECTIONAL_CHECKED) == APPID_SESSION_BIDIRECTIONAL_CHECKED)
            return flow_flags;

        if (dir == APP_ID_FROM_INITIATOR)
        {
            if (!getAppIdExtFlag(session, APPID_SESSION_INITIATOR_CHECKED))
            {
                flags = isIPMonitored(p, 0);
                flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                if (flags & IPFUNCS_USER_IP)
                    flow_flags |= APPID_SESSION_DISCOVER_USER;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;

                if (isSpecialSessionMonitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
            if (!(flow_flags & APPID_SESSION_DISCOVER_APP) && !getAppIdExtFlag(session, APPID_SESSION_RESPONDER_CHECKED))
            {
                flags = isIPMonitored(p, 1);
                if (flags & IPFUNCS_CHECKED)
                    flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;
                if (isSpecialSessionMonitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
        }
        else
        {
            if (!getAppIdExtFlag(session, APPID_SESSION_RESPONDER_CHECKED))
            {
                flags = isIPMonitored(p, 0);
                flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;
                if (isSpecialSessionMonitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
            if (!(flow_flags & APPID_SESSION_DISCOVER_APP) && !getAppIdExtFlag(session, APPID_SESSION_INITIATOR_CHECKED))
            {
                flags = isIPMonitored(p, 1);
                if (flags & IPFUNCS_CHECKED)
                    flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                if (flags & IPFUNCS_USER_IP)
                    flow_flags |= APPID_SESSION_DISCOVER_USER;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;
                if (isSpecialSessionMonitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
        }
    }
    else if (checkPortExclusion(p, 0))
    {
        flow_flags |= APPID_SESSION_INITIATOR_SEEN | APPID_SESSION_RESPONDER_SEEN | APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
    }
    else if (dir == APP_ID_FROM_INITIATOR)
    {
        flags = isIPMonitored(p, 0);
        flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
        if (flags & IPFUNCS_HOSTS_IP)
            flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
        if (flags & IPFUNCS_USER_IP)
            flow_flags |= APPID_SESSION_DISCOVER_USER;
        if (flags & IPFUNCS_APPLICATION)
            flow_flags |= APPID_SESSION_DISCOVER_APP;
        if (!(flow_flags & APPID_SESSION_DISCOVER_APP))
        {
            flags = isIPMonitored(p, 1);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
        }
        if (isSpecialSessionMonitored(p))
        {
            flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }
    }
    else
    {
        flags = isIPMonitored(p, 0);
        flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
        if (flags & IPFUNCS_HOSTS_IP)
            flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
        if (flags & IPFUNCS_APPLICATION)
            flow_flags |= APPID_SESSION_DISCOVER_APP;
        if (!(flow_flags & APPID_SESSION_DISCOVER_APP))
        {
            flags = isIPMonitored(p, 1);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
            if (flags & IPFUNCS_USER_IP)
                flow_flags |= APPID_SESSION_DISCOVER_USER;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
        }

        if (isSpecialSessionMonitored(p))
        {
            flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }
    }

    return flow_flags;
}

static inline void setServiceAppIdData(tAppIdData *session, tAppId serviceAppId, char *vendor, char **version)
{
    if (serviceAppId <= APP_ID_NONE)
        return;

    //in drambuie, 3rd party is in INIT state after processing first GET requuest.
    if (serviceAppId == APP_ID_HTTP)
    {
        if (session->clientServiceAppId == APP_ID_NONE)
        {
            session->clientServiceAppId = serviceAppId;
        }
        return;
    }

    if (session->serviceAppId != serviceAppId)
    {
        session->serviceAppId = serviceAppId;

        if (appidStaticConfig.instance_id)
            checkSandboxDetection(serviceAppId);

        /* Clear out previous values of vendor & version */
        if (session->serviceVendor)
        {
            free(session->serviceVendor);
            session->serviceVendor = NULL;
        }
        if (session->serviceVersion)
        {
            free(session->serviceVersion);
            session->serviceVersion = NULL;
        }

        if (vendor)
            session->serviceVendor = vendor;

        if (version && *version)
        {
            session->serviceVersion = *version;
            *version = NULL;
        }
    }
    else
    {
        if (vendor || version)
        {
            /* Clear previous values */
            if (session->serviceVendor)
                free(session->serviceVendor);
            if (session->serviceVersion)
                free(session->serviceVersion);

            /* set vendor */
            if (vendor)
                session->serviceVendor = vendor;
            else
                session->serviceVendor = NULL;

            /* set version */
            if (version && *version)
            {
                session->serviceVersion = *version;
                *version = NULL;
            }
            else
                session->serviceVersion = NULL;
        }
    }
}

static inline void setClientAppIdData(tAppIdData *session, tAppId clientAppId, char **version)
{
    tAppIdConfig *pConfig = appIdActiveConfigGet();
    if (clientAppId <= APP_ID_NONE || clientAppId == APP_ID_HTTP)
        return;

    if (session->clientAppId != clientAppId)
    {
        unsigned prev_priority = appInfoEntryPriorityGet(session->clientAppId, pConfig);
        unsigned curr_priority = appInfoEntryPriorityGet(clientAppId, pConfig) ;

        if (appidStaticConfig.instance_id)
            checkSandboxDetection(clientAppId);

        if ((session->clientAppId) && (prev_priority > curr_priority ))
            return;
        session->clientAppId = clientAppId;

        if (session->clientVersion)
            free(session->clientVersion);

        if (version && *version)
        {
            session->clientVersion = *version;
            *version = NULL;
        }
        else
            session->clientVersion = NULL;
    }
    else if (version && *version)
    {
        if (session->clientVersion)
            free(session->clientVersion);
        session->clientVersion = *version;
        *version = NULL;
    }
}

static inline void setReferredPayloadAppIdData(tAppIdData *session, tAppId referredPayloadAppId)
{
    if (referredPayloadAppId <= APP_ID_NONE)
        return;

    if (session->referredPayloadAppId != referredPayloadAppId)
    {
        if (appidStaticConfig.instance_id)
            checkSandboxDetection(referredPayloadAppId);

        session->referredPayloadAppId = referredPayloadAppId;
    }
}

static inline void setPayloadAppIdData(tAppIdData *session, tAppId payloadAppId, char **version)
{
    tAppIdConfig *pConfig = appIdActiveConfigGet();

    if (payloadAppId <= APP_ID_NONE)
        return;

    if (session->payloadAppId != payloadAppId)
    {
        unsigned prev_priority = appInfoEntryPriorityGet(session->payloadAppId, pConfig);
        unsigned curr_priority = appInfoEntryPriorityGet(payloadAppId, pConfig);

        if (appidStaticConfig.instance_id)
            checkSandboxDetection(payloadAppId);

        if ((session->payloadAppId ) && (prev_priority > curr_priority ))
            return;

        session->payloadAppId = payloadAppId;

        if (session->payloadVersion)
            free(session->payloadVersion);

        if (version && *version)
        {
            session->payloadVersion = *version;
            *version = NULL;
        }
        else
            session->payloadVersion = NULL;
    }
    else if (version && *version)
    {
        if (session->payloadVersion)
            free(session->payloadVersion);
        session->payloadVersion = *version;
        *version = NULL;
    }
}

static inline void clearSessionAppIdData(tAppIdData *session)
{
    session->payloadAppId = APP_ID_UNKNOWN;
    session->serviceAppId = APP_ID_UNKNOWN;
    session->tpPayloadAppId = APP_ID_UNKNOWN;
    session->tpAppId = APP_ID_UNKNOWN;
    if (session->payloadVersion)
    {
        free(session->payloadVersion);
        session->payloadVersion = NULL;
    }
    if (session->serviceVendor)
    {
        free(session->serviceVendor);
        session->serviceVendor = NULL;
    }
    if (session->serviceVersion)
    {
        free(session->serviceVersion);
        session->serviceVersion = NULL;
    }
    if (session->tsession)
    {
        appTlsSessionDataFree(session->tsession);
        session->tsession = NULL;
    }
    if (session->hsession)
    {
        appHttpSessionDataFree(session->hsession);
        session->hsession = NULL;
    }
    if (session->dsession)
    {
        appDNSSessionDataFree(session->dsession);
        session->dsession = NULL;
    }
    if (thirdparty_appid_module)
        thirdparty_appid_module->session_delete(session->tpsession, 1);
}

static inline int initial_CHP_sweep (PatternType current_ptype, char* chp_buffer,
        char **version, char **user, char **new_url,
        char **new_cookie, tAppIdData *session,
        const tAppIdConfig *pConfig)
{
    CHPApp* cah = NULL;
    tAppId candidate;
    int size, i;
    int found_in_buffer = 0;
    httpSession *hsession;
    int retVal = 0;

    hsession = session->hsession;

    if (chp_buffer && (size = strlen(chp_buffer)) &&
            (candidate = scanCHP(current_ptype, chp_buffer,
                                 size, version, user, new_url, new_cookie,
                                 &found_in_buffer, hsession, NULL, &pConfig->detectorHttpConfig)))
    {
        if ((cah = (CHPApp *)sfxhash_find(pConfig->CHP_glossary, &candidate)))
        {
            for (i = 0; i < NUMBER_OF_PTYPES; i++)
            {
                ptype_scan_counts[i] = cah->ptype_scan_counts[i];
                hsession->ptype_req_counts[i] = cah->ptype_req_counts[i];
                if (i > 3 && !cah->ptype_scan_counts[i] && !getAppIdExtFlag(session, APPID_SESSION_SPDY_SESSION))
                {
                    clearAppIdIntFlag(session, APPID_SESSION_CHP_INSPECTING);
                    if (thirdparty_appid_module)
                        thirdparty_appid_module->session_attr_clear(session->tpsession, TP_ATTR_CONTINUE_MONITORING);
                }
            }
            hsession->chp_candidate = cah->appId;
            hsession->app_type_flags = cah->app_type_flags;
            hsession->num_matches = cah->num_matches;
            hsession->num_scans = cah->num_scans;
            // we can only skip re-matching this if it is the only pattern of its type.
            if (ptype_scan_counts[current_ptype] == 1)
            {
                ptype_scan_counts[current_ptype]--;
                hsession->ptype_req_counts[current_ptype]--;
                hsession->num_scans--;
                hsession->total_found++;
            }

            retVal = 1;
        }
    }
    if (thirdparty_appid_module)
    {
        if ((ptype_scan_counts[CONTENT_TYPE_PT]))
            thirdparty_appid_module->session_attr_set(session->tpsession, TP_ATTR_COPY_RESPONSE_CONTENT);
        else
            thirdparty_appid_module->session_attr_clear(session->tpsession, TP_ATTR_COPY_RESPONSE_CONTENT);

        if ((ptype_scan_counts[LOCATION_PT]))
            thirdparty_appid_module->session_attr_set(session->tpsession, TP_ATTR_COPY_RESPONSE_LOCATION);
        else
            thirdparty_appid_module->session_attr_clear(session->tpsession, TP_ATTR_COPY_RESPONSE_LOCATION);

        if ((ptype_scan_counts[BODY_PT]))
            thirdparty_appid_module->session_attr_set(session->tpsession, TP_ATTR_COPY_RESPONSE_BODY);
        else
            thirdparty_appid_module->session_attr_clear(session->tpsession, TP_ATTR_COPY_RESPONSE_BODY);
    }

    return retVal;
}

static inline void processCHP(tAppIdData *session, char **version, SFSnortPacket *p, const tAppIdConfig *pConfig)
{
    int i, size;
    int found_in_buffer = 0;
    char *new_url = NULL;
    char *new_cookie = NULL;
    char *user = NULL;
    tAppId chp_final;
    tAppId ret = 0;
    httpSession *http_session = session->hsession;

    char *chp_buffers[NUMBER_OF_PTYPES] = {
        http_session->useragent,
        http_session->host,
        http_session->referer,
        http_session->uri,
        http_session->cookie,
        http_session->req_body,
        http_session->content_type,
        http_session->location,
        http_session->body,
    };

    if (http_session->chp_hold_flow)
        http_session->chp_finished = 0;

    if (!http_session->chp_candidate)
    {
        for (i = 0; i < 4; i++)
        {
            if ((initial_CHP_sweep((PatternType)i, chp_buffers[i],
                            version, &user, &new_url, &new_cookie,
                            session, pConfig)))
                break;
        }
        if (!http_session->chp_candidate)
            http_session->chp_finished = 1;
    }
    if (!http_session->chp_finished && http_session->chp_candidate)
    {
        for (i = 0; i < NUMBER_OF_PTYPES; i++)
        {
            if (ptype_scan_counts[i] && chp_buffers[i] && (size = strlen(chp_buffers[i])) > 0)
            {
                found_in_buffer = 0;
                ret = scanCHP((PatternType)i, chp_buffers[i], size, version,
                        &user, &new_url, &new_cookie, &found_in_buffer,
                        http_session, p, &pConfig->detectorHttpConfig);
                http_session->total_found += found_in_buffer;
                http_session->num_scans--;
                ptype_scan_counts[i] = 0;
                // Give up if scanCHP returns nothing, OR
                // (if we did not match the right numbher of patterns in this field AND EITHER
                // (there is no match quota [all must match]) OR
                // (the total number of matches is less than our match quota))
                if (!ret ||
                        (found_in_buffer < http_session->ptype_req_counts[i] &&
                         (!http_session->num_matches ||
                          http_session->total_found < http_session->num_matches)))
                {
                    http_session->chp_candidate = 0;
                    break;
                }
                /* We are finished if we have a num_matches target and we've met it or
                   if we have done all the scans */
                if (!http_session->num_scans ||
                        (http_session->num_matches && http_session->total_found >= http_session->num_matches))

                {
                    http_session->chp_finished = 1;
                    break;
                }
            }
            else if (ptype_scan_counts[i] && !http_session->chp_hold_flow)
            {
                /* we have a scan count, but nothing in the buffer, so we should drop out of CHP */
                http_session->chp_candidate = 0;
                break;
            }
        }
        if (!http_session->chp_candidate)
        {
            http_session->chp_finished = 1;
            if (*version)
            {
                free(*version);
                *version = NULL;
            }
            if (user)
            {
                free(user);
                user = NULL;
            }
            if (new_url)
            {
                free(new_url);
                new_url = NULL;
            }
            if (new_cookie)
            {
                free(new_cookie);
                new_cookie = NULL;
            }
            memset(ptype_scan_counts, 0, 7 * sizeof(ptype_scan_counts[0]));

            // Make it possible for other detectors to run.
            http_session->skip_simple_detect = false;
            return;
        }
        if (http_session->chp_candidate && http_session->chp_finished)
        {
            chp_final = http_session->chp_alt_candidate ? http_session->chp_alt_candidate : http_session->chp_candidate;
            if (http_session->app_type_flags & APP_TYPE_SERVICE)
            {
                setServiceAppIdData(session, chp_final, NULL, version);
            }
            if (http_session->app_type_flags & APP_TYPE_CLIENT)
            {
                setClientAppIdData(session, chp_final, version);
            }
            if (http_session->app_type_flags & APP_TYPE_PAYLOAD)
            {
                setPayloadAppIdData(session, chp_final, version);
            }
            if (http_session->fflow && http_session->fflow->flow_prepared)
            {
                finalizeFflow(http_session->fflow, http_session->app_type_flags,
                              (http_session->fflow->appId ? http_session->fflow->appId : chp_final), p);
                free(http_session->fflow);
                http_session->fflow = NULL;
            }
            if (*version)
                *version = NULL;
            if (user)
            {
                session->username = user;
                user = NULL;
                if (http_session->app_type_flags & APP_TYPE_SERVICE)
                    session->usernameService = chp_final;
                else
                    session->usernameService = session->serviceAppId;
                setAppIdExtFlag(session, APPID_SESSION_LOGIN_SUCCEEDED);
            }
            if (new_url)
            {
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s rewritten url: %s\n", app_id_debug_session, new_url);
                if (http_session->new_url)
                    free(http_session->new_url);
                http_session->new_url = new_url;
                new_url = NULL;
            }
            if (new_cookie)
            {
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s rewritten cookie: %s\n", app_id_debug_session, new_cookie);
                if (http_session->new_cookie)
                    free(http_session->new_cookie);
                http_session->new_cookie = new_cookie;
                new_cookie = NULL;
            }
            http_session->chp_candidate = 0;
            //if we're doing safesearch rewrites, we want to continue to hold the flow
            if (!http_session->get_offsets_from_rebuilt)
                http_session->chp_hold_flow = 0;
            session->scan_flags &= ~SCAN_HTTP_VIA_FLAG;
            session->scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
            session->scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
            memset(ptype_scan_counts, 0, 7 * sizeof(ptype_scan_counts[0]));
        }
        else /* if we have a candidate, but we're not finished */
        {
            if (user)
            {
                free(user);
                user = NULL;
            }
            if (new_url)
            {
                free(new_url);
                new_url = NULL;
            }
            if (new_cookie)
            {
                free(new_cookie);
                new_cookie = NULL;
            }
        }
    }
}

static inline bool payloadAppIdIsSet(tAppIdData *session)
{
    return ( session->payloadAppId || session->tpPayloadAppId );
}

static inline void clearMiscHttpFlags(tAppIdData *session)
{
    if (!getAppIdExtFlag(session, APPID_SESSION_SPDY_SESSION))
    {
        clearAppIdIntFlag(session, APPID_SESSION_CHP_INSPECTING);
        if (thirdparty_appid_module)
            thirdparty_appid_module->session_attr_clear(session->tpsession, TP_ATTR_CONTINUE_MONITORING);
    }
}

STATIC inline int processHTTPPacket(SFSnortPacket *p, tAppIdData *session, int direction, HttpParsedHeaders *const headers, const tAppIdConfig *pConfig)
{
#define RESPONSE_CODE_LENGTH 3
    HeaderMatchedPatterns hmp;
    httpSession *http_session;
    int start, end, size;
    char *version = NULL;
    char *vendorVersion = NULL;
    char *vendor = NULL;
    tAppId serviceAppId = 0;
    tAppId clientAppId = 0;
    tAppId payloadAppId = 0;
    tAppId referredPayloadAppId = 0;
    char *host;
    char *url;
    char *useragent;
    char *referer;
    char *via;
    PROFILE_VARS;
    PREPROC_PROFILE_START(httpPerfStats);

    http_session = session->hsession;
    if (!http_session)
    {
        clearSessionAppIdData(session);
        if (app_id_debug_session_flag)
            _dpd.logMsg("AppIdDbg %s attempt to process HTTP packet with no HTTP data\n", app_id_debug_session);
        PREPROC_PROFILE_END(httpPerfStats);
        return 0;
    }

    // For fragmented HTTP headers, do not process if none of the fields are set.
    // These fields will get set when the HTTP header is reassembled.
    if ((!http_session->useragent) && (!http_session->host) && (!http_session->referer) && (!http_session->uri))
    {
        if (!http_session->skip_simple_detect)
            clearMiscHttpFlags(session);
        PREPROC_PROFILE_END(httpPerfStats);
        return 0;
    }

    if (direction == APP_ID_FROM_RESPONDER && !getAppIdIntFlag(session, APPID_SESSION_RESPONSE_CODE_CHECKED))
    {
        if (http_session->response_code)
        {
            setAppIdIntFlag(session, APPID_SESSION_RESPONSE_CODE_CHECKED);
            if (strlen(http_session->response_code) != RESPONSE_CODE_LENGTH)
            {
                /* received bad response code. Stop processing this session */
                clearSessionAppIdData(session);
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s bad http response code\n", app_id_debug_session);
                PREPROC_PROFILE_END(httpPerfStats);
                return 0;
            }
        }
#if RESPONSE_CODE_PACKET_THRESHHOLD
        else if (++(http_session->response_code_packets) == RESPONSE_CODE_PACKET_THRESHHOLD)
        {
            setAppIdIntFlag(session, APPID_SESSION_RESPONSE_CODE_CHECKED);
            /* didn't receive response code in first X packets. Stop processing this session */
            clearSessionAppIdData(session);
            if (app_id_debug_session_flag)
                _dpd.logMsg("AppIdDbg %s no response code received\n", app_id_debug_session);
            PREPROC_PROFILE_END(httpPerfStats);
            return 0;
        }
#endif
    }
    host = http_session->host;
    url = http_session->url;
    via = http_session->via;
    useragent = http_session->useragent;
    referer = http_session->referer;
    memset(&hmp, 0, sizeof(hmp));

    if (session->serviceAppId == APP_ID_NONE)
    {
        session->serviceAppId = APP_ID_HTTP;
        if (appidStaticConfig.instance_id)
            checkSandboxDetection(APP_ID_HTTP);
    }

    if (app_id_debug_session_flag)
        _dpd.logMsg("AppIdDbg %s chp_finished %d chp_hold_flow %d\n", app_id_debug_session, http_session->chp_finished, http_session->chp_hold_flow);

    if (!http_session->chp_finished || http_session->chp_hold_flow)
        processCHP(session, &version, p, pConfig);

    if (!http_session->skip_simple_detect)  // false unless a match happened with a call to processCHP().
    {
        if (!getAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT))
        {
            // Scan Server Header for Vendor & Version
            if ((thirdparty_appid_module && (session->scan_flags & SCAN_HTTP_VENDOR_FLAG) && session->hsession->server) ||
                (!thirdparty_appid_module && getHTTPHeaderLocation(p->payload, p->payload_size, HTTP_ID_SERVER, &start, &end, &hmp, &pConfig->detectorHttpConfig) == 1))
            {
                if (session->serviceAppId == APP_ID_NONE || session->serviceAppId == APP_ID_HTTP)
                {
                    RNAServiceSubtype *subtype = NULL;
                    RNAServiceSubtype **tmpSubtype;

                    if (thirdparty_appid_module)
                        getServerVendorVersion(session->hsession->server, strlen(session->hsession->server), &vendorVersion, &vendor, &subtype);
                    else getServerVendorVersion(p->payload + start, end - start, &vendorVersion, &vendor, &subtype);
                    if (vendor || vendorVersion)
                    {
                        if (session->serviceVendor)
                        {
                            free(session->serviceVendor);
                            session->serviceVendor = NULL;
                        }
                        if (session->serviceVersion)
                        {
                            free(session->serviceVersion);
                            session->serviceVersion = NULL;
                        }
                        if (vendor)
                            session->serviceVendor = vendor;
                        if (vendorVersion)
                            session->serviceVersion = vendorVersion;
                        session->scan_flags &= ~SCAN_HTTP_VENDOR_FLAG;
                    }
                    if (subtype)
                    {
                        for (tmpSubtype = &session->subtype; *tmpSubtype; tmpSubtype = &(*tmpSubtype)->next);

                        *tmpSubtype = subtype;
                    }
                }
            }

            if (webdav_found(&hmp))
            {
                if (app_id_debug_session_flag && payloadAppId > APP_ID_NONE && session->payloadAppId != payloadAppId)
                    _dpd.logMsg("AppIdDbg %s payload is webdav\n", app_id_debug_session);
                setPayloadAppIdData(session, APP_ID_WEBDAV, NULL);
            }

            // Scan User-Agent for Browser types or Skype
            if ((session->scan_flags & SCAN_HTTP_USER_AGENT_FLAG) && session->clientAppId <= APP_ID_NONE && useragent && (size = strlen(useragent)) > 0)
            {
                if (version)
                {
                    free(version);
                    version = NULL;
                }
                identifyUserAgent((uint8_t *)useragent, size, &serviceAppId, &clientAppId, &version, &pConfig->detectorHttpConfig);
                if (app_id_debug_session_flag && serviceAppId > APP_ID_NONE && serviceAppId != APP_ID_HTTP && session->serviceAppId != serviceAppId)
                    _dpd.logMsg("AppIdDbg %s User Agent is service %d\n", app_id_debug_session, serviceAppId);
                setServiceAppIdData(session, serviceAppId, NULL, NULL);
                if (app_id_debug_session_flag && clientAppId > APP_ID_NONE && clientAppId != APP_ID_HTTP && session->clientAppId != clientAppId)
                    _dpd.logMsg("AppIdDbg %s User Agent is client %d\n", app_id_debug_session, clientAppId);
                setClientAppIdData(session, clientAppId, &version);
                session->scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
            }

            /* Scan Via Header for squid */
            if (!payloadAppIdIsSet(session) && (session->scan_flags & SCAN_HTTP_VIA_FLAG) && via && (size = strlen(via)) > 0)
            {
                if (version)
                {
                    free(version);
                    version = NULL;
                }
                payloadAppId = getAppidByViaPattern((uint8_t *)via, size, &version, &pConfig->detectorHttpConfig);
                if (app_id_debug_session_flag && payloadAppId > APP_ID_NONE && session->payloadAppId != payloadAppId)
                    _dpd.logMsg("AppIdDbg %s VIA is payload %d\n", app_id_debug_session, payloadAppId);
                setPayloadAppIdData(session, payloadAppId, NULL);
                session->scan_flags &= ~SCAN_HTTP_VIA_FLAG;
            }
        }

        /* Scan X-Working-With HTTP header */
        if ((thirdparty_appid_module && (session->scan_flags & SCAN_HTTP_XWORKINGWITH_FLAG) && session->hsession->x_working_with) ||
            (!thirdparty_appid_module && getHTTPHeaderLocation(p->payload, p->payload_size, HTTP_ID_X_WORKING_WITH, &start, &end, &hmp, &pConfig->detectorHttpConfig) == 1))
        {
            tAppId appId;

            if (thirdparty_appid_module)
                appId = scan_header_x_working_with(session->hsession->x_working_with, strlen(session->hsession->x_working_with), &version);
            else appId = scan_header_x_working_with(p->payload + start, end - start, &version);

            if (appId)
            {
                if (direction == APP_ID_FROM_INITIATOR)
                {
                    if (app_id_debug_session_flag && clientAppId > APP_ID_NONE && clientAppId != APP_ID_HTTP && session->clientAppId != clientAppId)
                        _dpd.logMsg("AppIdDbg %s X is client %d\n", app_id_debug_session, appId);
                    setClientAppIdData(session, appId, &version);
                }
                else
                {
                    if (app_id_debug_session_flag && serviceAppId > APP_ID_NONE && serviceAppId != APP_ID_HTTP && session->serviceAppId != serviceAppId)
                        _dpd.logMsg("AppIdDbg %s X is service %d\n", app_id_debug_session, appId);
                    setServiceAppIdData(session, appId, NULL, &version);
                }
                session->scan_flags &= ~SCAN_HTTP_XWORKINGWITH_FLAG;
            }
        }

        // Scan Content-Type Header for multimedia types and scan contents
        if ((thirdparty_appid_module && (session->scan_flags & SCAN_HTTP_CONTENT_TYPE_FLAG)
             && session->hsession->content_type  && !payloadAppIdIsSet(session)) ||
            (!thirdparty_appid_module && !payloadAppIdIsSet(session) &&
             getHTTPHeaderLocation(p->payload, p->payload_size, HTTP_ID_CONTENT_TYPE, &start, &end, &hmp, &pConfig->detectorHttpConfig) == 1))
        {
            if (thirdparty_appid_module)
                payloadAppId = getAppidByContentType(session->hsession->content_type, strlen(session->hsession->content_type), &pConfig->detectorHttpConfig);
            else payloadAppId = getAppidByContentType(p->payload + start, end - start, &pConfig->detectorHttpConfig);
            if (app_id_debug_session_flag && payloadAppId > APP_ID_NONE && session->payloadAppId != payloadAppId)
                _dpd.logMsg("AppIdDbg %s Content-Type is payload %d\n", app_id_debug_session, payloadAppId);
            setPayloadAppIdData(session, payloadAppId, NULL);
            session->scan_flags &= ~SCAN_HTTP_CONTENT_TYPE_FLAG;
        }

        if (session->scan_flags & SCAN_HTTP_HOST_URL_FLAG)
        {
            if (version)
            {
                free(version);
                version = NULL;
            }
            if (getAppIdFromUrl(host, url, &version, referer, &clientAppId, &serviceAppId, &payloadAppId, &referredPayloadAppId, 0, &pConfig->detectorHttpConfig) == 1)
            {
                // do not overwrite a previously-set client or service
                if (session->clientAppId <= APP_ID_NONE)
                {
                    if (app_id_debug_session_flag && clientAppId > APP_ID_NONE && clientAppId != APP_ID_HTTP && session->clientAppId != clientAppId)
                        _dpd.logMsg("AppIdDbg %s URL is client %d\n", app_id_debug_session, clientAppId);
                    setClientAppIdData(session, clientAppId, NULL);
                }
                if (session->serviceAppId <= APP_ID_NONE)
                {
                    if (app_id_debug_session_flag && serviceAppId > APP_ID_NONE && serviceAppId != APP_ID_HTTP && session->serviceAppId != serviceAppId)
                        _dpd.logMsg("AppIdDbg %s URL is service %d\n", app_id_debug_session, serviceAppId);
                    setServiceAppIdData(session, serviceAppId, NULL, NULL);
                }
                // DO overwrite a previously-set payload
                if (app_id_debug_session_flag && payloadAppId > APP_ID_NONE && session->payloadAppId != payloadAppId)
                    _dpd.logMsg("AppIdDbg %s URL is payload %d\n", app_id_debug_session, payloadAppId);
                setPayloadAppIdData(session, payloadAppId, &version);
                setReferredPayloadAppIdData(session, referredPayloadAppId);
            }
            session->scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
        }

        if (session->clientAppId == APP_ID_APPLE_CORE_MEDIA)
        {
            if (session->tpPayloadAppId > APP_ID_NONE)
            {
                session->miscAppId = session->clientAppId;
                session->clientAppId = session->tpPayloadAppId + GENERIC_APP_OFFSET;
            }
            else if (session->payloadAppId > APP_ID_NONE)
            {
                session->miscAppId = session->clientAppId;
                session->clientAppId = session->payloadAppId + GENERIC_APP_OFFSET;
            }
        }

        clearMiscHttpFlags(session);
    }  // end DON'T skip_simple_detect

    PREPROC_PROFILE_END(httpPerfStats);
    return 0;
}

static inline void stopRnaServiceInspection(SFSnortPacket *p, tAppIdData* session, int direction)
{
    sfaddr_t *ip;
    if (direction == APP_ID_FROM_INITIATOR)
    {
        ip = GET_DST_IP(p);
        session->service_ip = *ip;
        session->service_port = p->dst_port;
    }
    else
    {
        ip = GET_SRC_IP(p);
        session->service_ip = *ip;
        session->service_port = p->src_port;
    }
    session->rnaServiceState = RNA_STATE_FINISHED;
    setAppIdExtFlag(session, APPID_SESSION_SERVICE_DETECTED);
    clearAppIdExtFlag(session, APPID_SESSION_CONTINUE);
#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
    if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
        fprintf(SF_DEBUG_FILE, "%u -> %u %d stopping RNA service inspection\n",
            (unsigned)p->src_port, (unsigned)p->dst_port, IsTCP(p)? IPPROTO_TCP:IPPROTO_UDP);
#endif
}

static inline bool isSslDecryptionEnabled(tAppIdData *session)
{
    if (getAppIdExtFlag(session, APPID_SESSION_DECRYPTED))
        return 1;
#ifdef UNIT_TESTING
    if (session->session_packet_count >= 12)
        return 1;
    return 0;
#else
    return _dpd.streamAPI->is_session_decrypted(session->ssn);
#endif
}

static inline void checkRestartAppDetection(tAppIdData *session)
{
    if (getAppIdExtFlag(session, APPID_SESSION_DECRYPTED)) return;
    if (!isSslDecryptionEnabled(session)) return;

    tAppId serviceAppId = pickServiceAppId(session);
    bool isSsl = isSslServiceAppId(serviceAppId);

    // A session could either:
    // 1. Start of as SSL - captured with isSsl flag, OR
    // 2. It could start of as a non-SSL session and later change to SSL. For example, FTP->FTPS.
    //    In this case APPID_SESSION_ENCRYPTED flag is set by the protocol state machine.
    if (getAppIdExtFlag(session, APPID_SESSION_ENCRYPTED) || isSsl)
    {
#ifdef DEBUG_FW_APPID
        fprintf(SF_DEBUG_FILE, "SSL decryption is available, restarting app Detection\n");
#endif
        setAppIdExtFlag(session, APPID_SESSION_DECRYPTED);
        session->encrypted.serviceAppId = serviceAppId;
        session->encrypted.payloadAppId = pickPayloadId(session);
        session->encrypted.clientAppId = pickClientAppId(session);
        session->encrypted.miscAppId = pickMiscAppId(session);
        session->encrypted.referredAppId = pickReferredPayloadId(session);
        appSharedReInitData(session);
        if (app_id_debug_session_flag)
            _dpd.logMsg("AppIdDbg %s SSL decryption is available, restarting app Detection\n", app_id_debug_session);

        // APPID_SESSION_ENCRYPTED is set upon receiving a command which upgrades the session to SSL.
        // Next packet after the command will have encrypted traffic.
        // In the case of a session which starts as SSL, current packet itself is encrypted. Set the special flag
        // APPID_SESSION_APP_REINSPECT_SSL which allows reinspection of this pcaket.
        if (isSsl) setAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT_SSL);
    }
}

static inline void updateEncryptedAppId( tAppIdData *session, tAppId serviceAppId)
{
    switch (serviceAppId)
    {
        case APP_ID_HTTP:
            if (session->miscAppId == APP_ID_NSIIOPS || session->miscAppId == APP_ID_DDM_SSL
                    || session->miscAppId == APP_ID_MSFT_GC_SSL || session->miscAppId == APP_ID_SF_APPLIANCE_MGMT)
            {
                break;
            }
            session->miscAppId = APP_ID_HTTPS;
            break;
        case APP_ID_SMTP:
            session->miscAppId = APP_ID_SMTPS;
            break;
        case APP_ID_NNTP:
            session->miscAppId = APP_ID_NNTPS;
            break;
        case APP_ID_IMAP:
            session->miscAppId = APP_ID_IMAPS;
            break;
        case APP_ID_SHELL:
            session->miscAppId = APP_ID_SSHELL;
            break;
        case APP_ID_LDAP:
            session->miscAppId = APP_ID_LDAPS;
            break;
        case APP_ID_FTP_DATA:
            session->miscAppId = APP_ID_FTPSDATA;
            break;
        case APP_ID_FTP:
            session->miscAppId = APP_ID_FTPS;
            break;
        case APP_ID_TELNET:
            session->miscAppId = APP_ID_TELNET;
            break;
        case APP_ID_IRC:
            session->miscAppId = APP_ID_IRCS;
            break;
        case APP_ID_POP3:
            session->miscAppId = APP_ID_POP3S;
            break;
        default:
            break;
    }
}

static inline void ExamineSslMetadata(SFSnortPacket *p, tAppIdData *session, tAppIdConfig *pConfig)
{
    size_t size;
    int ret;
    tAppId clientAppId = 0;
    tAppId payloadAppId = 0;

    if ((session->scan_flags & SCAN_SSL_HOST_FLAG) && session->tsession->tls_host)
    {
        size = strlen(session->tsession->tls_host);
        if ((ret = ssl_scan_hostname((const u_int8_t *)session->tsession->tls_host, size, &clientAppId, &payloadAppId, &pConfig->serviceSslConfig)))
        {
            setClientAppIdData(session, clientAppId, NULL);
            setPayloadAppIdData(session, payloadAppId, NULL);
            setSSLSquelch(p, ret, (ret == 1 ? payloadAppId : clientAppId));
        }
        session->scan_flags &= ~SCAN_SSL_HOST_FLAG;
        // ret = 0;
    }
    if (session->tsession->tls_cname)
    {
        size = strlen(session->tsession->tls_cname);
        if ((ret = ssl_scan_cname((const u_int8_t *)session->tsession->tls_cname, size, &clientAppId, &payloadAppId, &pConfig->serviceSslConfig)))
        {
            setClientAppIdData(session, clientAppId, NULL);
            setPayloadAppIdData(session, payloadAppId, NULL);
            setSSLSquelch(p, ret, (ret == 1 ? payloadAppId : clientAppId));
        }
        free(session->tsession->tls_cname);
        session->tsession->tls_cname = NULL;
        // ret = 0;
    }
    if (session->tsession->tls_orgUnit)
    {
        size = strlen(session->tsession->tls_orgUnit);
        if ((ret = ssl_scan_cname((const u_int8_t *)session->tsession->tls_orgUnit, size, &clientAppId, &payloadAppId, &pConfig->serviceSslConfig)))
        {
            setClientAppIdData(session, clientAppId, NULL);
            setPayloadAppIdData(session, payloadAppId, NULL);
            setSSLSquelch(p, ret, (ret == 1 ? payloadAppId : clientAppId));
        }
        free(session->tsession->tls_orgUnit);
        session->tsession->tls_orgUnit = NULL;
        // ret = 0;
    }
}

static inline int RunClientDetectors(tAppIdData *session,
                              SFSnortPacket *p,
                              int direction,
                              tAppIdConfig *pConfig)
{
    int ret = CLIENT_APP_INPROCESS;

    if (session->clientData != NULL)
    {
        ret = session->clientData->validate(p->payload, p->payload_size, direction,
                                            session, p, session->clientData->userData, pConfig);
        if (app_id_debug_session_flag)
            _dpd.logMsg("AppIdDbg %s %s client detector returned %d\n", app_id_debug_session,
                        session->clientData->name ? session->clientData->name:"UNKNOWN", ret);
    }
    else if (    (session->candidate_client_list != NULL)
              && (sflist_count(session->candidate_client_list) > 0) )
    {
        SF_LNODE *node;
        tRNAClientAppModule *client;

        ret = CLIENT_APP_INPROCESS;
        node = sflist_first_node(session->candidate_client_list);
        while (node != NULL)
        {
            int result;
            SF_LNODE *node_tmp;

            client = (tRNAClientAppModule*)SFLIST_NODE_TO_DATA(node);
            result = client->validate(p->payload, p->payload_size, direction,
                                      session, p, client->userData, pConfig);
            if (app_id_debug_session_flag)
                _dpd.logMsg("AppIdDbg %s %s client detector returned %d\n", app_id_debug_session,
                            client->name ? client->name:"UNKNOWN", ret);

            node_tmp = node;
            node = sflist_next_node(session->candidate_client_list);
            if (result == CLIENT_APP_SUCCESS)
            {
                ret = CLIENT_APP_SUCCESS;
                session->clientData = client;
                sflist_free(session->candidate_client_list);
                session->candidate_client_list = NULL;
                break;    /* done */
            }
            else if (result != CLIENT_APP_INPROCESS)    /* fail */
            {
                sflist_remove_node(session->candidate_client_list, node_tmp);
            }
        }
    }

    return ret;
}

static inline void getOffsetsFromRebuilt(SFSnortPacket *pkt, httpSession *hsession)
{
// size of "GET /\r\n\r\n"
#define MIN_HTTP_REQ_HEADER_SIZE 9
    const uint8_t cookieStr[] = "Cookie: ";
    unsigned cookieStrLen = sizeof(cookieStr)-1;
    const uint8_t crlf[] = "\r\n";
    unsigned crlfLen = sizeof(crlf)-1;
    const uint8_t crlfcrlf[] = "\r\n\r\n";
    unsigned crlfcrlfLen = sizeof(crlfcrlf)-1;
    const uint8_t* p;
    uint8_t *headerEnd;
    uint16_t headerSize;

    if (!pkt || !pkt->payload || pkt->payload_size < MIN_HTTP_REQ_HEADER_SIZE)
        return;

    p = pkt->payload;

    if (!(headerEnd = (uint8_t *)service_strstr(p, pkt->payload_size, crlfcrlf, crlfcrlfLen)))
        return;

    headerEnd += crlfcrlfLen;

    headerSize = headerEnd - p;

    //uri offset is the index of the first char after the first space in the payload
    if (!(p = (uint8_t *)memchr(pkt->payload, ' ', headerSize)))
        return;
    hsession->uriOffset = ++p - pkt->payload;
    headerSize = headerEnd - p;

    //uri end offset is the index of the first CRLF sequence after uri offset
    if (!(p = (uint8_t *)service_strstr(p, headerSize, crlf, crlfLen)))
    {
        // clear uri offset if we can't find an end offset
        hsession->uriOffset = 0;
        return;
    }
    hsession->uriEndOffset = p - pkt->payload;
    headerSize = headerEnd - p;

    //cookie offset is the index of the first char after the cookie header, "Cookie: "
    if (!(p = (uint8_t *)service_strstr(p, headerSize, cookieStr, cookieStrLen)))
        return;
    hsession->cookieOffset = p + cookieStrLen - pkt->payload;
    headerSize = headerEnd - p;

    //cookie end offset is the index of the first CRLF sequence after cookie offset
    if (!(p = (uint8_t *)service_strstr(p, headerSize, crlf, crlfLen)))
    {
        // clear cookie offset if we can't find a cookie end offset
        hsession->cookieOffset = 0;
        return;
    }
    hsession->cookieEndOffset = p - pkt->payload;
}

static int16_t snortId_for_ftp;
static int16_t snortId_for_ftp_data;
static int16_t snortId_for_imap;
static int16_t snortId_for_pop3;
static int16_t snortId_for_smtp;

static inline void synchAppIdWithSnortId(tAppId newAppId, SFSnortPacket *p, tAppIdData *session, tAppIdConfig *pConfig)
{
    AppInfoTableEntry *entry;
    int16_t tempSnortId = session->snortId;

    if (tempSnortId == UNSYNCED_SNORT_ID)
    {
        tempSnortId = session->snortId = _dpd.sessionAPI->get_application_protocol_id(p->stream_session);
    }
    if (tempSnortId == snortId_for_ftp || tempSnortId == snortId_for_ftp_data ||
        tempSnortId == snortId_for_imap || tempSnortId == snortId_for_pop3 ||
        tempSnortId == snortId_for_smtp)
    {
        return; // FTP, IMAP, POP3, and SMTP preprocessors, in snort proper, already know and expect these to remain unchanged.
    }
    if ((entry = appInfoEntryGet(newAppId, pConfig)) && (tempSnortId = entry->snortId) && tempSnortId != session->snortId)
    {
        _dpd.sessionAPI->set_application_protocol_id(p->stream_session, tempSnortId);
        session->snortId = tempSnortId;
    }
}

static inline void checkTerminateTpModule(uint16_t tpPktCount, tAppIdData *session)
{
    if ((tpPktCount >= appidStaticConfig.max_tp_flow_depth) ||
        (getAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT) && getAppIdExtFlag(session, APPID_SESSION_HTTP_SESSION) &&
         session->hsession && session->hsession->uri &&
         (!session->hsession->chp_candidate || session->hsession->chp_finished)))
    {
        if (session->tpAppId == APP_ID_NONE)
            session->tpAppId = APP_ID_UNKNOWN;
        if (session->payloadAppId == APP_ID_NONE)
            session->payloadAppId = APP_ID_UNKNOWN;
        if (thirdparty_appid_module)
            thirdparty_appid_module->session_delete(session->tpsession, 1);
    }
}

void fwAppIdInit(void)
{
    /* init globals for snortId compares */
    snortId_for_ftp      = _dpd.findProtocolReference("ftp");
    snortId_for_ftp_data = _dpd.findProtocolReference("ftp-data");
    snortId_for_imap     = _dpd.findProtocolReference("imap");
    snortId_for_pop3     = _dpd.findProtocolReference("pop3");
    snortId_for_smtp     = _dpd.findProtocolReference("smtp");
}

void fwAppIdSearch(SFSnortPacket *p)
{
    tAppIdData *session;
    uint8_t protocol;
    tAppId tpAppId = 0;
    tAppId serviceAppId = 0;
    tAppId clientAppId = 0;
    tAppId payloadAppId = 0;
    bool isTpAppidDiscoveryDone = false;
    unsigned flow_flags;
    int direction;
    sfaddr_t *ip;
    uint16_t port;
    size_t size;
    int tp_confidence;
    tAppId* tp_proto_list;
    ThirdPartyAppIDAttributeData* tp_attribute_data;
#ifdef TARGET_BASED
    AppInfoTableEntry *entry;
#endif
    tAppIdConfig *pConfig = appIdActiveConfigGet();

    app_id_raw_packet_count++;

    if (!p->stream_session)
    {
        app_id_ignored_packet_count++;
        return;
    }

    if (p->flags & FLAG_REBUILT_STREAM && _dpd.streamAPI->is_session_decrypted(p->stream_session) == false)
    {
        session = getAppIdData(p->stream_session);
        if (session && session->hsession && session->hsession->get_offsets_from_rebuilt)
        {
            getOffsetsFromRebuilt(p, session->hsession);
            if (app_id_debug_session_flag)
                _dpd.logMsg("AppIdDbg %s offsets from rebuilt packet: uri: %u-%u cookie: %u-%u\n", app_id_debug_session, session->hsession->uriOffset, session->hsession->uriEndOffset, session->hsession->cookieOffset, session->hsession->cookieEndOffset);
        }
        app_id_ignored_packet_count++;
        return;
    }

    SetPacketRealTime(p->pkt_header->ts.tv_sec);

    session = appSharedGetData(p);
    if (session)
    {
#ifdef DEBUG_APP_ID_SESSIONS
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
        if (session->service_port == DEBUG_FW_APPID_PORT)
#endif
        {
            char src_ip[INET6_ADDRSTRLEN];
            char dst_ip[INET6_ADDRSTRLEN];

            src_ip[0] = 0;
            ip = GET_SRC_IP(p);
            inet_ntop(sfaddr_family(ip), (void *)sfaddr_get_ptr(ip), src_ip, sizeof(src_ip));
            dst_ip[0] = 0;
            ip = GET_DST_IP(p);
            inet_ntop(sfaddr_family(ip), (void *)sfaddr_get_ptr(ip), dst_ip, sizeof(dst_ip));
            fprintf(SF_DEBUG_FILE, "AppId Session %p %p for %s-%u -> %s-%u %d\n", session, session->ssn, src_ip,
                    (unsigned)p->src_port, dst_ip, (unsigned)p->dst_port, IsTCP(p) ? IPPROTO_TCP:IPPROTO_UDP);
        }
#endif
        if (session->common.fsf_type.flow_type == APPID_SESSION_TYPE_IGNORE)
            return;
        if (session->common.fsf_type.flow_type == APPID_SESSION_TYPE_NORMAL)
        {
            protocol = session->proto;
            session->ssn = p->stream_session;
        }
        else if (IsTCP(p))
            protocol = IPPROTO_TCP;
        else
            protocol = IPPROTO_UDP;
        ip = GET_SRC_IP(p);
        if (session->common.initiator_port)
            direction = (session->common.initiator_port == p->src_port) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
        else
            direction = (sfip_fast_equals_raw(ip, &session->common.initiator_ip)) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }
    else
    {
        if (IsTCP(p))
            protocol = IPPROTO_TCP;
        else if (IsUDP(p))
            protocol = IPPROTO_UDP;
        else if (p->ip4h)
            protocol = p->ip4h->ip_proto;
        else if (p->ip6h)
            protocol = p->ip6h->next;
        else
            return;
        direction = (_dpd.sessionAPI->get_packet_direction(p) & FLAG_FROM_CLIENT) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }

#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
    if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
    {
        char sipstr[INET6_ADDRSTRLEN];
        char dipstr[INET6_ADDRSTRLEN];

        sipstr[0] = 0;
        ip = GET_SRC_IP(p);
        inet_ntop(sfaddr_family(ip), (void *)sfaddr_get_ptr(ip), sipstr, sizeof(sipstr));
        dipstr[0] = 0;
        ip = GET_DST_IP(p);
        inet_ntop(sfaddr_family(ip), (void *)sfaddr_get_ptr(ip), dipstr, sizeof(dipstr));
        fprintf(SF_DEBUG_FILE, "%s-%u -> %s-%u %u\n", sipstr, (unsigned)p->src_port, dipstr, (unsigned)p->dst_port, (unsigned)protocol);
        /*DumpHex(SF_DEBUG_FILE, p->payload, p->payload_size); */
    }
#endif

    app_id_debug_session_flag = fwAppIdDebugCheck(p->stream_session, session, app_id_debug_flag,
            &app_id_debug_info, app_id_debug_session, direction);

    // fwAppIdSearch() is a top-level function that is called by AppIdProcess().
    // At this point, we know that we need to use the current active config -
    // pAppidActiveConfig. This function uses pAppidActiveConfig and passes it
    // to all the functions that need to look at AppId config.
    flow_flags = isSessionMonitored(p, direction, session);
    if (!(flow_flags & (APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED)))
    {
        if (!session)
        {
            if ((flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) == APPID_SESSION_BIDIRECTIONAL_CHECKED)
            {
                static APPID_SESSION_STRUCT_FLAG ignore_fsf = {.flow_type = APPID_SESSION_TYPE_IGNORE};
                _dpd.sessionAPI->set_application_data(p->stream_session, PP_APP_ID, &ignore_fsf, NULL);
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s not monitored\n", app_id_debug_session);
            }
            else
            {
                tTmpAppIdData *tmp_session;

                if (tmp_app_id_free_list)
                {
                    tmp_session = tmp_app_id_free_list;
                    tmp_app_id_free_list = tmp_session->next;
                }
                else if (!(tmp_session = malloc(sizeof(*tmp_session))))
                    DynamicPreprocessorFatalMessage("Could not allocate tTmpAppIdData data");
                tmp_session->common.fsf_type.flow_type = APPID_SESSION_TYPE_TMP;
                tmp_session->common.externalFlags = flow_flags;
                ip = (direction == APP_ID_FROM_INITIATOR) ? GET_SRC_IP(p) : GET_DST_IP(p);
                tmp_session->common.initiator_ip = *ip;
                if ((protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) && p->src_port != p->dst_port)
                    tmp_session->common.initiator_port = (direction == APP_ID_FROM_INITIATOR) ? p->src_port : p->dst_port;
                else
                    tmp_session->common.initiator_port = 0;
                tmp_session->common.policyId = appIdPolicyId;
                _dpd.sessionAPI->set_application_data(p->stream_session, PP_APP_ID,
                        tmp_session, (void (*)(void*))appTmpSharedDataFree);
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s unknown monitoring\n", app_id_debug_session);
            }
        }
        else
        {
            session->common.externalFlags = flow_flags;
            if ((flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) == APPID_SESSION_BIDIRECTIONAL_CHECKED)
                session->common.fsf_type.flow_type = APPID_SESSION_TYPE_IGNORE;
            session->common.policyId = appIdPolicyId;
            if (app_id_debug_session_flag)
                _dpd.logMsg("AppIdDbg %s not monitored\n", app_id_debug_session);
        }
        return;
    }

    if (!session || session->common.fsf_type.flow_type == APPID_SESSION_TYPE_TMP)
    {
        /* This call will free the existing temporary session, if there is one */
        session = appSharedCreateData(p, protocol, direction);
        if (app_id_debug_session_flag)
            _dpd.logMsg("AppIdDbg %s new session\n", app_id_debug_session);
    }

    app_id_processed_packet_count++;
    session->session_packet_count++;

    if (direction == APP_ID_FROM_INITIATOR)
        session->stats.initiatorBytes += p->pkt_header->pktlen;
    else
        session->stats.responderBytes += p->pkt_header->pktlen;

    session->common.externalFlags = flow_flags;
    session->common.policyId = appIdPolicyId;

    tpAppId = session->tpAppId;

    session->common.policyId = appIdPolicyId;

#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
    if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
    {
#endif
        fprintf(SF_DEBUG_FILE, "%u %u -> %u %u Begin %d %u - (%d %d %d %d %d) %u %08X %08X (%u %u %u)\n",
                (unsigned )session->session_packet_count, (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol, direction,
                (unsigned)p->payload_size, session->serviceAppId, session->clientAppId, session->payloadAppId, tpAppId, session->miscAppId,
                session->rnaServiceState, session->common.externalFlags, p->flags, thirdparty_appid_module->session_state_get(session->tpsession),
                (unsigned)session->init_tpPackets, (unsigned)session->resp_tpPackets);
        /*DumpHex(SF_DEBUG_FILE, p->payload, p->payload_size); */
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
    }
#endif
#endif

    if (p->flags & FLAG_STREAM_ORDER_BAD)
        setAppIdExtFlag(session, APPID_SESSION_OOO);
    else if (p->tcp_header)
    {
        if ((p->tcp_header->flags & TCPHEADER_RST) && session->previous_tcp_flags == TCPHEADER_SYN)
        {
            AppIdServiceIDState *id_state;

            setAppIdExtFlag(session, APPID_SESSION_SYN_RST);
            if (sfaddr_is_set(&session->service_ip))
            {
                ip = &session->service_ip;
                port = session->service_port;
            }
            else
            {
                ip = GET_SRC_IP(p);
                port = p->src_port;
            }
            id_state = AppIdGetServiceIDState(ip, IPPROTO_TCP, port, AppIdServiceDetectionLevel(session));
            if (id_state)
            {
                if (!id_state->reset_time)
                    id_state->reset_time = GetPacketRealTime;
                else if ((GetPacketRealTime - id_state->reset_time) >= 60)
                {
                    AppIdRemoveServiceIDState(ip, IPPROTO_TCP, port, AppIdServiceDetectionLevel(session));
                    setAppIdExtFlag(session, APPID_SESSION_SERVICE_DELETED);
                }
            }
        }
        session->previous_tcp_flags = p->tcp_header->flags;
    }


    /*HostPort based AppId.  */
    if (!(session->scan_flags & SCAN_HOST_PORT_FLAG))
    {
        tHostPortVal *hv;
        int16_t snortId;

        session->scan_flags |= SCAN_HOST_PORT_FLAG;
        if (direction == APP_ID_FROM_INITIATOR)
        {
            ip = GET_DST_IP(p);
            port = p->dst_port;
        }
        else
        {
            ip = GET_SRC_IP(p);
            port = p->src_port;
        }
        if ((hv = hostPortAppCacheFind(ip, port, protocol, pConfig)) > APP_ID_NONE)
        {
            switch (hv->type)
            {
            case 1:
                session->clientAppId = hv->appId;
                session->rnaClientState = RNA_STATE_FINISHED;
                break;
            case 2:
                session->payloadAppId = hv->appId;
                break;
            default:
                session->serviceAppId = hv->appId;
                synchAppIdWithSnortId(hv->appId, p, session, pConfig);
                session->rnaServiceState = RNA_STATE_FINISHED;
                session->rnaClientState = RNA_STATE_FINISHED;
                setAppIdExtFlag(session, APPID_SESSION_SERVICE_DETECTED);
                if (thirdparty_appid_module)
                    thirdparty_appid_module->session_delete(session->tpsession, 1);
                session->tpsession = NULL;
            }
        }
    }

    checkRestartAppDetection(session);

    //restart inspection by 3rd party
    if (TPIsAppIdDone(session->tpsession) && getAppIdExtFlag(session, APPID_SESSION_HTTP_SESSION) && p->payload_size)
    {
        if (session->tpReinspectByInitiator)
        {
            clearAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT);
            if (direction == APP_ID_FROM_RESPONDER)
                session->tpReinspectByInitiator = 0; //toggle at OK response
        }
        else if (direction == APP_ID_FROM_INITIATOR)
        {
            session->tpReinspectByInitiator = 1;     //once per request
            setAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT);
            if (app_id_debug_session_flag)
                _dpd.logMsg("AppIdDbg %s 3rd party allow reinspect http\n", app_id_debug_session);
            appHttpFieldClear(session->hsession);
        }
    }

    if (session->tpAppId == APP_ID_SSH && session->payloadAppId != APP_ID_SFTP && session->session_packet_count >= MIN_SFTP_PACKET_COUNT && session->session_packet_count < MAX_SFTP_PACKET_COUNT)
    {
        if (GET_IPH_TOS(p) == 8)
        {
            session->payloadAppId = APP_ID_SFTP;
            if (app_id_debug_session_flag)
                _dpd.logMsg("AppIdDbg %s payload is SFTP\n", app_id_debug_session);
        }
    }

    PROFILE_VARS;
    PREPROC_PROFILE_START(tpPerfStats);

    if ( thirdparty_appid_module && (!getAppIdIntFlag(session, APPID_SESSION_APP_NO_TPI)) && (!TPIsAppIdDone(session->tpsession) || getAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT | APPID_SESSION_APP_REINSPECT_SSL)))
    {
        // First SSL decrypted packet is now being inspected. Reset the flag so that SSL decrypted traffic
        // gets processed like regular traffic from next packet onwards
        if (getAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT_SSL))
        {
            clearAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT_SSL);
        }
        if (p->payload_size || appidStaticConfig.tp_allow_probes)
        {
            if (protocol != IPPROTO_TCP || (p->flags & FLAG_STREAM_ORDER_OK) || appidStaticConfig.tp_allow_probes)
            {
                PREPROC_PROFILE_START(tpLibPerfStats);
                if (!session->tpsession)
                {
                    if (!(session->tpsession = thirdparty_appid_module->session_create()))
                        DynamicPreprocessorFatalMessage("Could not allocate tAppIdData->tpsession data");
                }
                thirdparty_appid_module->session_process(session->tpsession, p, direction,
                                                         &tpAppId, &tp_confidence, &tp_proto_list, &tp_attribute_data);
                PREPROC_PROFILE_END(tpLibPerfStats);
                isTpAppidDiscoveryDone = true;
                if (thirdparty_appid_module->session_state_get(session->tpsession) == TP_STATE_CLASSIFIED)
                    clearAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT);

                // if the NAVL appId must be treated as a client, do it now
                if (appInfoEntryFlagGet(tpAppId, APPINFO_FLAG_TP_CLIENT, appIdActiveConfigGet()))
                    session->clientAppId = tpAppId;

                ProcessThirdPartyResults(session, tp_confidence, tp_proto_list, tp_attribute_data);

                if (getAppIdExtFlag(session, APPID_SESSION_SSL_SESSION) &&
                    !(session->scan_flags & SCAN_SSL_HOST_FLAG))
                {
                    setSSLSquelch(p, 1, tpAppId);
                }

                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s 3rd party returned %d\n", app_id_debug_session, tpAppId);
#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                    fprintf(SF_DEBUG_FILE, "%u -> %u %u 3rd party returned %d\n",
                            (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol, tpAppId);
#endif
                if (appInfoEntryFlagGet(tpAppId, APPINFO_FLAG_IGNORE, pConfig))
                      tpAppId = APP_ID_NONE;
            }
            else
            {
                tpAppId = APP_ID_NONE;
#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                    fprintf(SF_DEBUG_FILE, "%u -> %u %u Skipping ooo\n",
                            (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol);
#endif
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s 3rd party packet out-of-order\n", app_id_debug_session);
            }

            if (thirdparty_appid_module->session_state_get(session->tpsession) == TP_STATE_MONITORING)
            {
                thirdparty_appid_module->disable_flags(session->tpsession, TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING | TP_SESSION_FLAG_FUTUREFLOW);
            }

            if(tpAppId == APP_ID_SSL && (_dpd.sessionAPI->get_application_protocol_id(p->stream_session) == snortId_for_ftp_data))
            {
                //  If we see SSL on an FTP data channel set tpAppId back
                //  to APP_ID_NONE so the FTP preprocessor picks up the flow.
                tpAppId = APP_ID_NONE;
            }

            if (tpAppId > APP_ID_NONE && (!getAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT) || session->payloadAppId > APP_ID_NONE))
            {
#ifdef TARGET_BASED
                tAppId snortAppId;
                int16_t snortId;
#endif

                // if the packet is HTTP, then search for via pattern
                if (getAppIdExtFlag(session, APPID_SESSION_HTTP_SESSION) && session->hsession)
                {
#ifdef TARGET_BASED
                    snortAppId = APP_ID_HTTP;
#endif
                    //payload should never be APP_ID_HTTP
                    if (tpAppId != APP_ID_HTTP)
                        session->tpPayloadAppId = tpAppId;

#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                    if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                        fprintf(SF_DEBUG_FILE, "%u -> %u %u tp identified http payload %d\n",
                                (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol, tpAppId);
#endif

                    session->tpAppId = APP_ID_HTTP;

                    processHTTPPacket(p, session, direction, NULL, appIdActiveConfigGet());

                    if (TPIsAppIdAvailable(session->tpsession) && session->tpAppId == APP_ID_HTTP
                                                        && !getAppIdIntFlag(session, APPID_SESSION_APP_REINSPECT))
                    {
                        session->rnaClientState = RNA_STATE_FINISHED;
                        setAppIdExtFlag(session, APPID_SESSION_CLIENT_DETECTED);
                        session->rnaServiceState = RNA_STATE_FINISHED;
                        setAppIdExtFlag(session, APPID_SESSION_SERVICE_DETECTED);
                        clearAppIdExtFlag(session, APPID_SESSION_CONTINUE);
                        if (direction == APP_ID_FROM_INITIATOR)
                        {
                            ip = GET_DST_IP(p);
                            session->service_ip = *ip;
                            session->service_port = p->dst_port;
                        }
                        else
                        {
                            ip = GET_SRC_IP(p);
                            session->service_ip = *ip;
                            session->service_port = p->src_port;
                        }
                    }
                }
                else if (getAppIdExtFlag(session, APPID_SESSION_SSL_SESSION) && session->tsession)
                {
                    ExamineSslMetadata(p, session, pConfig);

                    uint16_t serverPort;
                    tAppId portAppId;

                    serverPort = (direction == APP_ID_FROM_INITIATOR)? p->dst_port:p->src_port;

                    portAppId = getSslServiceAppId(serverPort);
                    if (tpAppId == APP_ID_SSL )
                    {
                        tpAppId = portAppId;

                        //SSL policy needs to determine IMAPS/POP3S etc before appId sees first server packet
                        session->portServiceAppId = portAppId;

                        if (app_id_debug_session_flag)
                            _dpd.logMsg("AppIdDbg %s SSL is service %d, portServiceAppId %d\n",
                                    app_id_debug_session, tpAppId, session->portServiceAppId);
                    }
                    else
                    {
                        session->tpPayloadAppId = tpAppId;
                        tpAppId = portAppId;
                        if (app_id_debug_session_flag)
                            _dpd.logMsg("AppIdDbg %s SSL is %d\n", app_id_debug_session, tpAppId);
                    }
                    session->tpAppId = tpAppId;
#ifdef TARGET_BASED
                    snortAppId = APP_ID_SSL;
#endif

#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                    if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                        fprintf(SF_DEBUG_FILE, "%u -> %u %u tp identified ssl service %d\n",
                                (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol, tpAppId);
#endif
                }
                else
                {
                    //for non-http protocols, tp id is treated like serviceId

#ifdef TARGET_BASED
                    snortAppId = tpAppId;
#endif

#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                    if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                        fprintf(SF_DEBUG_FILE, "%u -> %u %u tp identified non-http service %d\n",
                                (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol, tpAppId);
#endif
                    session->tpAppId = tpAppId;
                }

#ifdef TARGET_BASED
                synchAppIdWithSnortId(snortAppId, p, session, pConfig);
#endif
            }
            else
            {
                if (protocol != IPPROTO_TCP || (p->flags & (FLAG_STREAM_ORDER_OK | FLAG_STREAM_ORDER_BAD)))
                {
                    if (direction == APP_ID_FROM_INITIATOR)
                    {
                        session->init_tpPackets++;
                        checkTerminateTpModule(session->init_tpPackets, session);
                    }
                    else
                    {
                        session->resp_tpPackets++;
                        checkTerminateTpModule(session->resp_tpPackets, session);
                    }
                }
            }
        }
    }
    PREPROC_PROFILE_END(tpPerfStats);

    if (direction == APP_ID_FROM_RESPONDER && !getAppIdExtFlag(session, APPID_SESSION_PORT_SERVICE_DONE|APPID_SESSION_SYN_RST))
    {
        setAppIdExtFlag(session, APPID_SESSION_PORT_SERVICE_DONE);
        session->portServiceAppId = getPortServiceId(protocol, p->src_port, pConfig);
        if (app_id_debug_session_flag)
            _dpd.logMsg("AppIdDbg %s port service %d\n", app_id_debug_session, session->portServiceAppId);
    }

    /* Length-based detectors. */
    /* Only check if:
     *  - Port service didn't find anything (and we haven't yet either).
     *  - We haven't hit the max packets allowed for detector sequence matches.
     *  - Packet has data (we'll ignore 0-sized packets in sequencing). */
    if (   (session->portServiceAppId <= APP_ID_NONE)
        && (session->length_sequence.sequence_cnt < LENGTH_SEQUENCE_CNT_MAX)
        && (p->payload_size > 0))
    {
        uint8_t index = session->length_sequence.sequence_cnt;
        session->length_sequence.proto = protocol;
        session->length_sequence.sequence_cnt++;
        session->length_sequence.sequence[index].direction = direction;
        session->length_sequence.sequence[index].length    = p->payload_size;
        session->portServiceAppId = lengthAppCacheFind(&session->length_sequence, pConfig);
        if (session->portServiceAppId > APP_ID_NONE)
        {
            setAppIdExtFlag(session, APPID_SESSION_PORT_SERVICE_DONE);
        }
    }

    /* exceptions for rexec and any other service detector that needs to see SYN and SYN/ACK */
    if (getAppIdIntFlag(session, APPID_SESSION_REXEC_STDERR))
    {
        AppIdDiscoverService(p, direction, session, pConfig);
        if(session->serviceAppId == APP_ID_DNS && appidStaticConfig.dns_host_reporting && session->dsession && session->dsession->host )
        {
            size = session->dsession->host_len;
            dns_host_scan_hostname((const u_int8_t *)session->dsession->host, size, &clientAppId, &payloadAppId, &pConfig->serviceDnsConfig);
            setClientAppIdData(session, clientAppId, NULL);
        }
        else if (session->serviceAppId == APP_ID_RTMP)
            ExamineRtmpMetadata(session);
        else if (getAppIdExtFlag(session, APPID_SESSION_SSL_SESSION) && session->tsession)
            ExamineSslMetadata(p, session, pConfig);
    }

    //service
    else if (protocol != IPPROTO_TCP || (p->flags & FLAG_STREAM_ORDER_OK))
    {
        if (session->rnaServiceState != RNA_STATE_FINISHED)
        {
            uint32_t prevRnaServiceState;
            PREPROC_PROFILE_START(serviceMatchPerfStats);

            tpAppId = session->tpAppId;
            prevRnaServiceState = session->rnaServiceState;

            //decision to directly call validator or go through elaborate service_state tracking
            //is made once at the beginning of sesssion.
            if (session->rnaServiceState == RNA_STATE_NONE && p->payload_size)
            {
                if (_dpd.sessionAPI->get_session_flags(p->stream_session) & SSNFLAG_MIDSTREAM)
                {
                    // Unless it could be ftp control
                    if (protocol == IPPROTO_TCP && (p->src_port == 21 || p->dst_port == 21) &&
                            !(p->tcp_header->flags & (TCPHEADER_FIN | TCPHEADER_RST)))
                    {
                        setAppIdExtFlag(session, APPID_SESSION_CLIENT_DETECTED | APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
                        if (!AddFTPServiceState(session))
                        {
                            setAppIdExtFlag(session, APPID_SESSION_CONTINUE);
                            if (p->dst_port != 21)
                                setAppIdExtFlag(session, APPID_SESSION_RESPONDER_SEEN);
                        }
                        session->rnaServiceState = RNA_STATE_STATEFUL;
                    }
                    else
                    {
                        setAppIdExtFlag(session, APPID_SESSION_MID | APPID_SESSION_SERVICE_DETECTED);
                        session->rnaServiceState = RNA_STATE_FINISHED;
                    }
                }
                else if (TPIsAppIdAvailable(session->tpsession))
                {
                    if (tpAppId > APP_ID_NONE)
                    {
                        //tp has positively identified appId, Dig deeper only if sourcefire detector
                        //identifies additional information or flow is UDP reveresed.
                        if ((entry = appInfoEntryGet(tpAppId, pConfig))
                                && entry->svrValidator &&
                                ((entry->flags & APPINFO_FLAG_SERVICE_ADDITIONAL) ||
                                 ((entry->flags & APPINFO_FLAG_SERVICE_UDP_REVERSED) && protocol == IPPROTO_UDP &&
                                  getAppIdExtFlag(session, APPID_SESSION_INITIATOR_MONITORED | APPID_SESSION_RESPONDER_MONITORED))))
                        {
                            AppIdFlowdataDeleteAllByMask(session, APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);

#ifdef DEBUG_FW_APPID
                            if (session->serviceData && compareServiceElements(session->serviceData, entry->svrValidator))
                            {
                                fprintf(stderr, "Mismatched validator Original %s, new tp %s",
                                        session->serviceData->name, entry->svrValidator->name);
                            }
#endif
                            session->serviceData = entry->svrValidator;
                            session->rnaServiceState = RNA_STATE_STATEFUL;
#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                            if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                                fprintf(SF_DEBUG_FILE, "%u -> %u %u RNA doing deeper inspection\n",
                                        (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol);
#endif
                        }
                        else
                        {
                            stopRnaServiceInspection(p, session, direction);
                        }
                    }
                    else
                        session->rnaServiceState = RNA_STATE_STATEFUL;
                }
                else
                    session->rnaServiceState = RNA_STATE_STATEFUL;
            }

            //stop rna inspection as soon as tp has classified a valid AppId later in the session
            if (session->rnaServiceState == RNA_STATE_STATEFUL && prevRnaServiceState == RNA_STATE_STATEFUL
                    && TPIsAppIdAvailable(session->tpsession) && tpAppId > APP_ID_NONE  && tpAppId < SF_APPID_MAX )
            {
                entry = appInfoEntryGet(tpAppId, pConfig);

                if (entry && entry->svrValidator && !(entry->flags & APPINFO_FLAG_SERVICE_ADDITIONAL))
                {
                    stopRnaServiceInspection(p, session, direction);
                }
            }

            if (session->rnaServiceState == RNA_STATE_STATEFUL)
            {
#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                    fprintf(SF_DEBUG_FILE, "%u -> %u %u RNA identifying service\n",
                            (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol);
#endif
                AppIdDiscoverService(p, direction, session, pConfig);
                isTpAppidDiscoveryDone = true;
                //to stop executing validator after service has been detected by RNA.
                if (getAppIdExtFlag(session, APPID_SESSION_SERVICE_DETECTED) && !getAppIdExtFlag(session, APPID_SESSION_CONTINUE))
                    session->rnaServiceState = RNA_STATE_FINISHED;

                if(session->serviceAppId == APP_ID_DNS && appidStaticConfig.dns_host_reporting && session->dsession && session->dsession->host  )
                {
                    size = session->dsession->host_len;
                    dns_host_scan_hostname((const u_int8_t *)session->dsession->host , size, &clientAppId, &payloadAppId, &pConfig->serviceDnsConfig);
                    setClientAppIdData(session, clientAppId, NULL);
                }
                else if (session->serviceAppId == APP_ID_RTMP)
                    ExamineRtmpMetadata(session);
                else if (getAppIdExtFlag(session, APPID_SESSION_SSL_SESSION) && session->tsession)
                    ExamineSslMetadata(p, session, pConfig);

#ifdef TARGET_BASED
                if (tpAppId <= APP_ID_NONE && getAppIdExtFlag(session, APPID_SESSION_SERVICE_DETECTED) &&
                        !getAppIdExtFlag(session, APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_IGNORE_HOST))
                {
                    synchAppIdWithSnortId(session->serviceAppId, p, session, pConfig);
                }
#endif
            }
            PREPROC_PROFILE_END(serviceMatchPerfStats);
        }

        if (session->rnaClientState != RNA_STATE_FINISHED)
        {
            PREPROC_PROFILE_START(clientMatchPerfStats);
            uint32_t prevRnaClientState = session->rnaClientState;

            //decision to directly call validator or go through elaborate service_state tracking
            //is made once at the beginning of sesssion.
            if (session->rnaClientState == RNA_STATE_NONE && p->payload_size && direction == APP_ID_FROM_INITIATOR)
            {
                if (_dpd.sessionAPI->get_session_flags(p->stream_session) & SSNFLAG_MIDSTREAM)
                    session->rnaClientState = RNA_STATE_FINISHED;
                else if (TPIsAppIdAvailable(session->tpsession) && (tpAppId = session->tpAppId) > APP_ID_NONE && tpAppId < SF_APPID_MAX)
                {
                    if ((entry = appInfoEntryGet(tpAppId, pConfig)) && entry->clntValidator &&
                            ((entry->flags & APPINFO_FLAG_CLIENT_ADDITIONAL) ||
                             ((entry->flags & APPINFO_FLAG_CLIENT_USER) &&
                              getAppIdExtFlag(session, APPID_SESSION_DISCOVER_USER))))
                    {
                        //tp has positively identified appId, Dig deeper only if sourcefire detector
                        //identifies additional information
                        session->clientData = entry->clntValidator;
                        session->rnaClientState = RNA_STATE_DIRECT;
                    }
                    else
                    {
                        setAppIdExtFlag(session, APPID_SESSION_CLIENT_DETECTED);
                        session->rnaClientState = RNA_STATE_FINISHED;
                    }
                }
                else if (getAppIdExtFlag(session, APPID_SESSION_HTTP_SESSION))
                    session->rnaClientState = RNA_STATE_FINISHED;
                else
                    session->rnaClientState = RNA_STATE_STATEFUL;
            }

            //stop rna inspection as soon as tp has classified a valid AppId later in the session
            if ((session->rnaClientState == RNA_STATE_STATEFUL || session->rnaClientState == RNA_STATE_DIRECT) && session->rnaClientState == prevRnaClientState
                    && TPIsAppIdAvailable(session->tpsession) && tpAppId > APP_ID_NONE  && tpAppId < SF_APPID_MAX )
            {
                entry = appInfoEntryGet(tpAppId, pConfig);

                if (!(entry && entry->clntValidator && entry->clntValidator == session->clientData && (entry->flags & (APPINFO_FLAG_CLIENT_ADDITIONAL|APPINFO_FLAG_CLIENT_USER))))
                {
                    session->rnaClientState = RNA_STATE_FINISHED;
                    setAppIdExtFlag(session, APPID_SESSION_CLIENT_DETECTED);
                }
            }

            if (session->rnaClientState == RNA_STATE_DIRECT)
            {
                int ret = CLIENT_APP_INPROCESS;

#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                    fprintf(SF_DEBUG_FILE, "%u -> %u %u RNA identifying additional client info\n",
                            (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol);
#endif
                if (direction == APP_ID_FROM_INITIATOR)
                {
                    /* get out if we've already tried to validate a client app */
                    if (!getAppIdExtFlag(session, APPID_SESSION_CLIENT_DETECTED))
                    {
                        ret = RunClientDetectors(session, p, direction, pConfig);
                    }
                }
                else if (session->rnaServiceState != RNA_STATE_STATEFUL &&
                         getAppIdExtFlag(session, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))
                {
                    ret = RunClientDetectors(session, p, direction, pConfig);
                }

#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                    fprintf(SF_DEBUG_FILE, "%u -> %u %u direct client validate returned %d\n",
                            (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol, ret);
#endif
                switch (ret)
                {
                    case CLIENT_APP_INPROCESS:
                        break;
                    default:
                        session->rnaClientState = RNA_STATE_FINISHED;
                        break;
                }
            }
            else if (session->rnaClientState == RNA_STATE_STATEFUL)
            {
#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
                    fprintf(SF_DEBUG_FILE, "%u -> %u %u RNA identifying client\n",
                            (unsigned)p->src_port, (unsigned)p->dst_port, (unsigned)protocol);
#endif
                AppIdDiscoverClientApp(p, direction, session, pConfig);
                isTpAppidDiscoveryDone = true;
                if (session->candidate_client_list != NULL)
                {
                    if (sflist_count(session->candidate_client_list) > 0)
                    {
                        int ret = 0;
                        if (direction == APP_ID_FROM_INITIATOR)
                        {
                            /* get out if we've already tried to validate a client app */
                            if (!getAppIdExtFlag(session, APPID_SESSION_CLIENT_DETECTED))
                            {
                                ret = RunClientDetectors(session, p, direction, pConfig);
                            }
                        }
                        else if (session->rnaServiceState != RNA_STATE_STATEFUL &&
                                 getAppIdExtFlag(session, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))
                        {
                            ret = RunClientDetectors(session, p, direction, pConfig);
                        }
                        if (ret < 0)
                            setAppIdExtFlag(session, APPID_SESSION_CLIENT_DETECTED);
                    }
                    else
                    {
                        setAppIdExtFlag(session, APPID_SESSION_CLIENT_DETECTED);
                    }
                }
            }
            PREPROC_PROFILE_END(clientMatchPerfStats);
        }

        setAppIdExtFlag(session, APPID_SESSION_ADDITIONAL_PACKET);
    }
    else
    {
#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
                if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
#endif
        fprintf(SF_DEBUG_FILE, "Packet not okay\n");
#endif
        if (app_id_debug_session_flag && p->payload_size)
            _dpd.logMsg("AppIdDbg %s packet out-of-order\n", app_id_debug_session);
    }

    serviceAppId = pickServiceAppId(session);
    payloadAppId = pickPayloadId(session);

    if (serviceAppId > APP_ID_NONE)
    {
        if (getAppIdExtFlag(session, APPID_SESSION_DECRYPTED))
        {
            if (session->miscAppId == APP_ID_NONE)
                updateEncryptedAppId(session, serviceAppId);
        }
        else if (isTpAppidDiscoveryDone && isSslServiceAppId(serviceAppId) && _dpd.isSSLPolicyEnabled(NULL))
            setAppIdExtFlag(session, APPID_SESSION_CONTINUE);
    }

    _dpd.streamAPI->set_application_id(p->stream_session, serviceAppId, pickClientAppId(session), payloadAppId, pickMiscAppId(session));

    if (serviceAppId > APP_ID_NONE)
    {
        if (payloadAppId > APP_ID_NONE && payloadAppId != session->pastIndicator)
        {
            session->pastIndicator = payloadAppId;
            checkSessionForAFIndicator(p, direction, pConfig, payloadAppId);
        }

        if (session->payloadAppId == APP_ID_NONE && session->pastForecast != serviceAppId && session->pastForecast != APP_ID_UNKNOWN)
        {
            session->pastForecast = checkSessionForAFForecast(session, p, direction, pConfig, serviceAppId);
        }
    }

#ifdef DEBUG_FW_APPID
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
    if (p->dst_port == DEBUG_FW_APPID_PORT || p->src_port == DEBUG_FW_APPID_PORT)
    {
#endif
        fprintf(SF_DEBUG_FILE, "%u %u -> %u %u End %d %u - (%d %d %d %d %d) %u %08X %u %u %u\n", (unsigned)session->session_packet_count, (unsigned)p->src_port, (unsigned)p->dst_port,
                (unsigned)protocol, direction, (unsigned)p->payload_size,
                session->serviceAppId, session->clientAppId, session->payloadAppId,
                session->tpAppId, session->miscAppId, session->rnaServiceState, session->common.externalFlags, thirdparty_appid_module->session_state_get(session->tpsession),
                (unsigned)session->init_tpPackets, (unsigned)session->resp_tpPackets);
        //DumpHex(SF_DEBUG_FILE, p->payload, p->payload_size);
#if defined(DEBUG_FW_APPID_PORT) && DEBUG_FW_APPID_PORT
    }
#endif
#endif
}

static inline void ProcessThirdPartyResults(tAppIdData* appIdSession, int confidence, tAppId* proto_list, ThirdPartyAppIDAttributeData* attribute_data)
{
    int size;
    tAppId serviceAppId = 0;
    tAppId clientAppId = 0;
    tAppId payloadAppId = 0;
    tAppId referredPayloadAppId = 0;
    tAppIdConfig *pConfig = appIdActiveConfigGet();

    if (ThirdPartyAppIDFoundProto(APP_ID_EXCHANGE, proto_list))
    {
        if (!appIdSession->payloadAppId)
            appIdSession->payloadAppId = APP_ID_EXCHANGE;
    }

    if (ThirdPartyAppIDFoundProto(APP_ID_HTTP, proto_list))
    {
        if (app_id_debug_session_flag)
            _dpd.logMsg("AppIdDbg %s flow is HTTP\n", app_id_debug_session);
        setAppIdExtFlag(appIdSession, APPID_SESSION_HTTP_SESSION);
    }
    if (ThirdPartyAppIDFoundProto(APP_ID_SPDY, proto_list))
    {
        if (app_id_debug_session_flag)
            _dpd.logMsg("AppIdDbg %s flow is SPDY\n", app_id_debug_session);

        setAppIdExtFlag(appIdSession, APPID_SESSION_HTTP_SESSION);
        setAppIdExtFlag(appIdSession, APPID_SESSION_SPDY_SESSION);
    }

    if (getAppIdExtFlag(appIdSession, APPID_SESSION_HTTP_SESSION))
    {
        if (!appIdSession->hsession)
        {
            if (!(appIdSession->hsession = calloc(1, sizeof(*appIdSession->hsession))))
                DynamicPreprocessorFatalMessage("Could not allocate httpSession data");
            memset(ptype_scan_counts, 0, 7 * sizeof(ptype_scan_counts[0]));
        }

        if (getAppIdExtFlag(appIdSession, APPID_SESSION_SPDY_SESSION))
        {
            if (attribute_data->spdyRequestHost)
            {
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s SPDY host is %s\n", app_id_debug_session, attribute_data->spdyRequestHost);
                if (appIdSession->hsession->host)
                {
                    free(appIdSession->hsession->host);
                    appIdSession->hsession->chp_finished = 0;
                }
                if (NULL != (appIdSession->hsession->host = strdup(attribute_data->spdyRequestHost)))
                    appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->spdyRequestPath)
            {
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s SPDY URI is %s\n", app_id_debug_session, attribute_data->spdyRequestPath);
                if (appIdSession->hsession->uri)
                {
                    free(appIdSession->hsession->uri);
                    appIdSession->hsession->chp_finished = 0;
                }
                appIdSession->hsession->uri = strdup(attribute_data->spdyRequestPath); // mem alloc fail benign
            }
            if (attribute_data->spdyRequestScheme &&
                attribute_data->spdyRequestHost &&
                attribute_data->spdyRequestPath)
            {
                static const char httpsScheme[] = "https";
                static const char httpScheme[] = "http";
                const char *scheme;

                if (appIdSession->hsession->url)
                {
                    free(appIdSession->hsession->url);
                    appIdSession->hsession->chp_finished = 0;
                }
                if (getAppIdExtFlag(appIdSession, APPID_SESSION_DECRYPTED)
                        && memcmp(attribute_data->spdyRequestScheme, httpScheme, sizeof(httpScheme)-1) == 0)
                {
                    scheme = httpsScheme;
                }
                else
                {
                    scheme = attribute_data->spdyRequestScheme;
                }

                size = strlen(scheme) +
                       strlen(attribute_data->spdyRequestHost) +
                       strlen(attribute_data->spdyRequestPath) +
                       sizeof("://"); // see sprintf() format
                if (NULL != (appIdSession->hsession->url = malloc(size)))
                {
                    sprintf(appIdSession->hsession->url, "%s://%s%s",
                         scheme, attribute_data->spdyRequestHost,
                         attribute_data->spdyRequestPath);
                    appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
                }
            }
            if (attribute_data->spdyRequestScheme)
            {
                free(attribute_data->spdyRequestScheme);
                attribute_data->spdyRequestScheme = NULL;
            }
            if (attribute_data->spdyRequestHost)
            {
                free(attribute_data->spdyRequestHost);
                attribute_data->spdyRequestHost = NULL;
            }
            if (attribute_data->spdyRequestPath)
            {
                free(attribute_data->spdyRequestPath);
                attribute_data->spdyRequestPath = NULL;
            }
        }
        else
        {
            if (attribute_data->httpRequestHost)
            {
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s HTTP host is %s\n", app_id_debug_session, attribute_data->httpRequestHost);
                if (appIdSession->hsession->host)
                {
                    free(appIdSession->hsession->host);
                    if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                        appIdSession->hsession->chp_finished = 0;
                }
                appIdSession->hsession->host = attribute_data->httpRequestHost;
                attribute_data->httpRequestHost = NULL;
                appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->httpRequestUrl)
            {
                static const char httpScheme[] = "http://";

                if (appIdSession->hsession->url)
                {
                    free(appIdSession->hsession->url);
                    if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                        appIdSession->hsession->chp_finished = 0;
                }

                //change http to https if session was decrypted.
                if (getAppIdExtFlag(appIdSession, APPID_SESSION_DECRYPTED)
                        && memcmp(attribute_data->httpRequestUrl, httpScheme, sizeof(httpScheme)-1) == 0)
                {
                    appIdSession->hsession->url = malloc(strlen(attribute_data->httpRequestUrl) + 2);

                    if (appIdSession->hsession->url)
                        sprintf(appIdSession->hsession->url, "https://%s", attribute_data->httpRequestUrl + sizeof(httpScheme)-1);

                    free(attribute_data->httpRequestUrl);
                    attribute_data->httpRequestUrl = NULL;
                }
                else
                {
                    appIdSession->hsession->url = attribute_data->httpRequestUrl;
                    attribute_data->httpRequestUrl = NULL;
                }

                appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->httpRequestUri)
            {
                if (appIdSession->hsession->uri)
                {
                    free(appIdSession->hsession->uri);
                    if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                        appIdSession->hsession->chp_finished = 0;
                }
                appIdSession->hsession->uri = attribute_data->httpRequestUri;
                appIdSession->hsession->uriOffset = attribute_data->httpRequestUriOffset;
                appIdSession->hsession->uriEndOffset = attribute_data->httpRequestUriEndOffset;
                attribute_data->httpRequestUri = NULL;
                attribute_data->httpRequestUriOffset = 0;
                attribute_data->httpRequestUriEndOffset = 0;
                if (app_id_debug_session_flag)
                    _dpd.logMsg("AppIdDbg %s uri (%u-%u) is %s\n", app_id_debug_session, appIdSession->hsession->uriOffset, appIdSession->hsession->uriEndOffset, appIdSession->hsession->uri);
            }
        }
        if (attribute_data->httpRequestVia)
        {
            if (appIdSession->hsession->via)
            {
                free(appIdSession->hsession->via);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->via = attribute_data->httpRequestVia;
            attribute_data->httpRequestVia = NULL;
            appIdSession->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        else if (attribute_data->httpResponseVia)
        {
            if (appIdSession->hsession->via)
            {
                free(appIdSession->hsession->via);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->via = attribute_data->httpResponseVia;
            attribute_data->httpResponseVia = NULL;
            appIdSession->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        if (attribute_data->httpRequestUserAgent)
        {
            if (appIdSession->hsession->useragent)
            {
                free(appIdSession->hsession->useragent);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->useragent = attribute_data->httpRequestUserAgent;
            attribute_data->httpRequestUserAgent = NULL;
            appIdSession->scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        }
        if (attribute_data->httpResponseCode)
        {
            if (appIdSession->hsession->response_code)
            {
                free(appIdSession->hsession->response_code);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->response_code = attribute_data->httpResponseCode;
            attribute_data->httpResponseCode = NULL;
        }
        if (!appidStaticConfig.referred_appId_disabled && attribute_data->httpRequestReferer)
        {
            if (app_id_debug_session_flag)
                _dpd.logMsg("AppIdDbg %s referrer is %s\n", app_id_debug_session, attribute_data->httpRequestReferer);
            if (appIdSession->hsession->referer)
            {
                free(appIdSession->hsession->referer);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->referer = attribute_data->httpRequestReferer;
            attribute_data->httpRequestReferer = NULL;
        }
        if (attribute_data->httpRequestCookie)
        {
            if (appIdSession->hsession->cookie)
            {
                free(appIdSession->hsession->cookie);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->cookie = attribute_data->httpRequestCookie;
            appIdSession->hsession->cookieOffset = attribute_data->httpRequestCookieOffset;
            appIdSession->hsession->cookieEndOffset = attribute_data->httpRequestCookieEndOffset;
            attribute_data->httpRequestCookie = NULL;
            attribute_data->httpRequestCookieOffset = 0;
            attribute_data->httpRequestCookieEndOffset = 0;
            if (app_id_debug_session_flag)
                _dpd.logMsg("AppIdDbg %s cookie (%u-%u) is %s\n", app_id_debug_session, appIdSession->hsession->cookieOffset, appIdSession->hsession->cookieEndOffset, appIdSession->hsession->cookie);
        }
        if (attribute_data->httpResponseContent)
        {
            if (appIdSession->hsession->content_type)
            {
                free(appIdSession->hsession->content_type);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->content_type = attribute_data->httpResponseContent;
            attribute_data->httpResponseContent = NULL;
            appIdSession->scan_flags |= SCAN_HTTP_CONTENT_TYPE_FLAG;
        }
        if (ptype_scan_counts[LOCATION_PT] && attribute_data->httpResponseLocation)
        {
            if (appIdSession->hsession->location)
            {
                free(appIdSession->hsession->location);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->location = attribute_data->httpResponseLocation;
            attribute_data->httpResponseLocation = NULL;
        }
        if (attribute_data->httpRequestBody)
        {
            if (app_id_debug_session_flag)
                _dpd.logMsg("AppIdDbg %s got a request body %s\n", app_id_debug_session, attribute_data->httpRequestBody);
            if (appIdSession->hsession->req_body)
            {
                free(appIdSession->hsession->req_body);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->req_body = attribute_data->httpRequestBody;
            attribute_data->httpRequestBody = NULL;
        }
        if (ptype_scan_counts[BODY_PT] && attribute_data->httpResponseBody)
        {
            if (appIdSession->hsession->body)
            {
                free(appIdSession->hsession->body);
                if (!getAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->body = attribute_data->httpResponseBody;
            attribute_data->httpResponseBody = NULL;
        }
        if (!appIdSession->hsession->chp_finished || appIdSession->hsession->chp_hold_flow)
        {
            setAppIdIntFlag(appIdSession, APPID_SESSION_CHP_INSPECTING);
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_attr_set(appIdSession->tpsession, TP_ATTR_CONTINUE_MONITORING);
        }
        if (attribute_data->httpResponseServer)
        {
            if (appIdSession->hsession->server)
                free(appIdSession->hsession->server);
            appIdSession->hsession->server = attribute_data->httpResponseServer;
            attribute_data->httpResponseServer = NULL;
            appIdSession->scan_flags |= SCAN_HTTP_VENDOR_FLAG;
        }
        if (attribute_data->httpRequestXWorkingWith)
        {
            if (appIdSession->hsession->x_working_with)
                free(appIdSession->hsession->x_working_with);
            appIdSession->hsession->x_working_with = attribute_data->httpRequestXWorkingWith;
            attribute_data->httpRequestXWorkingWith = NULL;
            appIdSession->scan_flags |= SCAN_HTTP_XWORKINGWITH_FLAG;
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_RTMP, proto_list) ||
             ThirdPartyAppIDFoundProto(APP_ID_RTSP, proto_list))
    {
        if (!appIdSession->hsession)
        {
            if (!(appIdSession->hsession = calloc(1, sizeof(*appIdSession->hsession))))
                DynamicPreprocessorFatalMessage("Could not allocate httpSession data");
        }
        if (!appIdSession->hsession->url)
        {
            if (attribute_data->httpRequestUrl)
            {
                appIdSession->hsession->url = attribute_data->httpRequestUrl;
                attribute_data->httpRequestUrl = NULL;
                appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
        }

        if (!appidStaticConfig.referred_appId_disabled && !appIdSession->hsession->referer)
        {
            if (attribute_data->httpRequestReferer)
            {
                appIdSession->hsession->referer = attribute_data->httpRequestReferer;
                attribute_data->httpRequestReferer = NULL;
            }
        }

        if (appIdSession->hsession->url || (confidence == 100 && appIdSession->session_packet_count > appidStaticConfig.rtmp_max_packets))
        {
            if (appIdSession->hsession->url)
            {
                if (((getAppIdFromUrl(NULL, appIdSession->hsession->url, NULL,
                                    appIdSession->hsession->referer, &clientAppId, &serviceAppId,
                                    &payloadAppId, &referredPayloadAppId, 1, &pConfig->detectorHttpConfig)) ||
                            (getAppIdFromUrl(NULL, appIdSession->hsession->url, NULL,
                                             appIdSession->hsession->referer, &clientAppId, &serviceAppId,
                                             &payloadAppId, &referredPayloadAppId, 0, &pConfig->detectorHttpConfig))) == 1)

                {
                    // do not overwrite a previously-set client or service
                    if (appIdSession->clientAppId <= APP_ID_NONE)
                        setClientAppIdData(appIdSession, clientAppId, NULL);
                    if (appIdSession->serviceAppId <= APP_ID_NONE)
                        setServiceAppIdData(appIdSession, serviceAppId, NULL, NULL);

                    // DO overwrite a previously-set payload
                    setPayloadAppIdData(appIdSession, payloadAppId, NULL);
                    setReferredPayloadAppIdData(appIdSession, referredPayloadAppId);
                }
            }

            if (thirdparty_appid_module)
            {
                thirdparty_appid_module->disable_flags(appIdSession->tpsession, TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING | TP_SESSION_FLAG_FUTUREFLOW);
                thirdparty_appid_module->session_delete(appIdSession->tpsession, 1);
            }
            appIdSession->tpsession = NULL;
            clearAppIdIntFlag(appIdSession, APPID_SESSION_APP_REINSPECT);
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_SSL, proto_list))
    {
        tAppId tmpAppId = APP_ID_NONE;

        if (thirdparty_appid_module && appIdSession->tpsession)
            tmpAppId = thirdparty_appid_module->session_appid_get(appIdSession->tpsession);

        setAppIdExtFlag(appIdSession, APPID_SESSION_SSL_SESSION);

        if (!appIdSession->tsession)
        {
            if (!(appIdSession->tsession = calloc(1, sizeof(*appIdSession->tsession))))
                DynamicPreprocessorFatalMessage("Could not allocate tlsSession data");
        }

        if (!appIdSession->clientAppId)
            setClientAppIdData(appIdSession, APP_ID_SSL_CLIENT, NULL);

        if (attribute_data->tlsHost)
        {
            if (appIdSession->tsession->tls_host)
                free(appIdSession->tsession->tls_host);
            appIdSession->tsession->tls_host = attribute_data->tlsHost;
            attribute_data->tlsHost = NULL;
            if (testSSLAppIdForReinspect(tmpAppId))
                appIdSession->scan_flags |= SCAN_SSL_HOST_FLAG;
        }
        if (testSSLAppIdForReinspect(tmpAppId))
        {
            if (attribute_data->tlsCname)
            {
                if (appIdSession->tsession->tls_cname)
                    free(appIdSession->tsession->tls_cname);
                appIdSession->tsession->tls_cname = attribute_data->tlsCname;
                attribute_data->tlsCname = NULL;
            }
            if (attribute_data->tlsOrgUnit)
            {
                if (appIdSession->tsession->tls_orgUnit)
                    free(appIdSession->tsession->tls_orgUnit);
                appIdSession->tsession->tls_orgUnit = attribute_data->tlsOrgUnit;
                attribute_data->tlsOrgUnit = NULL;
            }
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_FTP_CONTROL, proto_list))
    {
        if (!appidStaticConfig.ftp_userid_disabled && attribute_data->ftpCommandUser)
        {
            if (appIdSession->username)
                free(appIdSession->username);
            appIdSession->username = attribute_data->ftpCommandUser;
            attribute_data->ftpCommandUser = NULL;
            appIdSession->usernameService = APP_ID_FTP_CONTROL;
            setAppIdExtFlag(appIdSession, APPID_SESSION_LOGIN_SUCCEEDED);
        }
    }
}

void appSetServiceValidator(RNAServiceValidationFCN fcn, tAppId appId, unsigned extractsInfo, tAppIdConfig *pConfig)
{
    AppInfoTableEntry* pEntry = appInfoEntryGet(appId, pConfig);
    if (!pEntry)
    {
        _dpd.errMsg("AppId", "Invalid direct service AppId, %d, for %p", appId, fcn);
        return;
    }
    extractsInfo &= (APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_SERVICE_UDP_REVERSED);
    if (!extractsInfo)
    {
        _dpd.debugMsg(DEBUG_LOG, "Ignoring direct service without info for %p with AppId %d", fcn, appId);
        return;
    }
    pEntry->svrValidator = ServiceGetServiceElement(fcn, NULL, pConfig);
    if (pEntry->svrValidator)
        pEntry->flags |= extractsInfo;
    else
        _dpd.errMsg("AppId", "Failed to find a service element for %p with AppId %d", fcn, appId);
}

void appSetLuaServiceValidator(RNAServiceValidationFCN fcn, tAppId appId, unsigned extractsInfo, struct _Detector *data)
{
    AppInfoTableEntry *entry;
    tAppIdConfig *pConfig = appIdNewConfigGet();

    if ((entry = appInfoEntryGet(appId, pConfig)))
    {

        entry->flags |= APPINFO_FLAG_ACTIVE;

        extractsInfo &= (APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_SERVICE_UDP_REVERSED);
        if (!extractsInfo)
        {
            _dpd.debugMsg(DEBUG_LOG,"Ignoring direct service without info for %p %p with AppId %d\n",fcn, data, appId);
            return;
        }

        entry->svrValidator = ServiceGetServiceElement(fcn, data, pConfig);
        if (entry->svrValidator)
            entry->flags |= extractsInfo;
        else
            _dpd.errMsg("AppId: Failed to find a service element for %p %p with AppId %d", fcn, data, appId);
    }
    else
    {
        _dpd.errMsg("Invalid direct service AppId, %d, for %p %p\n",appId, fcn, data);
    }
}

void appSetClientValidator(RNAClientAppFCN fcn, tAppId appId, unsigned extractsInfo, tAppIdConfig *pConfig)
{
    AppInfoTableEntry* pEntry = appInfoEntryGet(appId, pConfig);
    if (!pEntry)
    {
        _dpd.errMsg("AppId", "Invalid direct client application AppId, %d, for %p", appId, fcn);
        return;
    }
    extractsInfo &= (APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER);
    if (!extractsInfo)
    {
        _dpd.debugMsg(DEBUG_LOG, "Ignoring direct client application without info for %p with AppId %d", fcn, appId);
        return;
    }
    pEntry->clntValidator = ClientAppGetClientAppModule(fcn, NULL, &pConfig->clientAppConfig);
    if (pEntry->clntValidator)
        pEntry->flags |= extractsInfo;
    else
        _dpd.errMsg("AppId", "Failed to find a client application module for %p with AppId %d", fcn, appId);
}

void appSetLuaClientValidator(RNAClientAppFCN fcn, tAppId appId, unsigned extractsInfo, struct _Detector *data)
{
    AppInfoTableEntry* entry;
    tAppIdConfig *pConfig = appIdNewConfigGet();

    if ((entry = appInfoEntryGet(appId, pConfig)))
    {
        entry->flags |= APPINFO_FLAG_ACTIVE;
        extractsInfo &= (APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER);
        if (!extractsInfo)
        {
            _dpd.debugMsg(DEBUG_LOG,"Ignoring direct client application without info for %p %p with AppId %d\n",fcn, data, appId);
            return;
        }

        entry->clntValidator = ClientAppGetClientAppModule(fcn, data, &pConfig->clientAppConfig);
        if (entry->clntValidator)
            entry->flags |= extractsInfo;
        else
            _dpd.errMsg("AppId: Failed to find a client application module for %p %p with AppId %d", fcn, data, appId);
    }
    else
    {
        _dpd.errMsg("Invalid direct client application AppId, %d, for %p %p\n",appId, fcn, data);
        return;
    }
}

void AppIdAddUser(tAppIdData *flowp, const char *username, tAppId appId, int success)
{
    if (flowp->username)
        free(flowp->username);
    flowp->username = strdup(username);
    if (!flowp->username)
        DynamicPreprocessorFatalMessage("Could not allocate username data");

    flowp->usernameService = appId;
    if (success)
        setAppIdExtFlag(flowp, APPID_SESSION_LOGIN_SUCCEEDED);
    else
        clearAppIdExtFlag(flowp, APPID_SESSION_LOGIN_SUCCEEDED);
}

void AppIdAddDnsQueryInfo(tAppIdData *flow,
                          uint16_t id,
                          const uint8_t *host, uint8_t host_len, uint16_t host_offset,
                          uint16_t record_type)
{
    if (!flow->dsession)
    {
        if (!(flow->dsession = calloc(1, sizeof(*flow->dsession))))
            DynamicPreprocessorFatalMessage("Could not allocate dnsSession data");
    }
    else if ((flow->dsession->state != 0) && (flow->dsession->id != id))
    {
        AppIdResetDnsInfo(flow);
    }

    if (flow->dsession->state & DNS_GOT_QUERY)
        return;
    flow->dsession->state |= DNS_GOT_QUERY;

    flow->dsession->id          = id;
    flow->dsession->record_type = record_type;

    if (!flow->dsession->host)
    {
        if ((host != NULL) && (host_len > 0) && (host_offset > 0))
        {
            flow->dsession->host_len    = host_len;
            flow->dsession->host_offset = host_offset;
            flow->dsession->host        = dns_parse_host(host, host_len);
        }
    }
}

void AppIdAddDnsResponseInfo(tAppIdData *flow,
                             uint16_t id,
                             const uint8_t *host, uint8_t host_len, uint16_t host_offset,
                             uint8_t response_type, uint32_t ttl)
{
    if (!flow->dsession)
    {
        if (!(flow->dsession = calloc(1, sizeof(*flow->dsession))))
            DynamicPreprocessorFatalMessage("Could not allocate dnsSession data");
    }
    else if ((flow->dsession->state != 0) && (flow->dsession->id != id))
    {
        AppIdResetDnsInfo(flow);
    }

    if (flow->dsession->state & DNS_GOT_RESPONSE)
        return;
    flow->dsession->state |= DNS_GOT_RESPONSE;

    flow->dsession->id            = id;
    flow->dsession->response_type = response_type;
    flow->dsession->ttl           = ttl;

    if (!flow->dsession->host)
    {
        if ((host != NULL) && (host_len > 0) && (host_offset > 0))
        {
            flow->dsession->host_len    = host_len;
            flow->dsession->host_offset = host_offset;
            flow->dsession->host        = dns_parse_host(host, host_len);
        }
    }
}

void AppIdResetDnsInfo(tAppIdData *flow)
{
    if (flow->dsession)
    {
        free(flow->dsession->host);
        memset(flow->dsession, 0, sizeof(*(flow->dsession)));
    }
}

void AppIdAddPayload(tAppIdData *flow, tAppId payload_id)
{
    if (appidStaticConfig.instance_id)
        checkSandboxDetection(payload_id);
    flow->payloadAppId = payload_id;
}

tAppId getOpenAppId(void *ssnptr)
{
    tAppIdData *session;
    tAppId payloadAppId = APP_ID_NONE;
    if (ssnptr && (session = getAppIdData(ssnptr)))
    {
        payloadAppId = session->payloadAppId;
    }

    return payloadAppId;
}

/**
 * @returns 1 if some appid is found, 0 otherwise.
 */
int sslAppGroupIdLookup(void *ssnptr, const char * serverName, const char * commonName,
        tAppId *serviceAppId, tAppId *clientAppId, tAppId *payloadAppId)
{
    tAppIdData *session;
    *serviceAppId = *clientAppId = *payloadAppId = APP_ID_NONE;

    if (commonName)
    {
        ssl_scan_cname((const uint8_t *)commonName, strlen(commonName), clientAppId, payloadAppId, &pAppidActiveConfig->serviceSslConfig);
    }
    if (serverName)
    {
        ssl_scan_hostname((const uint8_t *)serverName, strlen(serverName), clientAppId, payloadAppId, &pAppidActiveConfig->serviceSslConfig);
    }

    if (ssnptr && (session = getAppIdData(ssnptr)))

    {
        *serviceAppId = pickServiceAppId(session);
        if(*clientAppId == APP_ID_NONE) {
            *clientAppId = pickClientAppId(session);
        }
        if(*payloadAppId == APP_ID_NONE) {
            *payloadAppId = pickPayloadId(session);
        }

    }
    if(*serviceAppId != APP_ID_NONE ||
            *clientAppId != APP_ID_NONE ||
            *payloadAppId != APP_ID_NONE)
    {
        return 1;
    }
    return 0;
}

void httpHeaderCallback (SFSnortPacket *p, HttpParsedHeaders *const headers)
{
    tAppIdData *session;
    int direction;
    tAppIdConfig *pConfig = appIdActiveConfigGet();

    if (thirdparty_appid_module)
        return;
    if (!p || !(session = getAppIdData(p->stream_session)))
        return;

    direction = (_dpd.sessionAPI->get_packet_direction(p) & FLAG_FROM_CLIENT) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

#ifdef DEBUG_APP_ID_SESSIONS
    {
            char src_ip[INET6_ADDRSTRLEN];
            char dst_ip[INET6_ADDRSTRLEN];
            sfaddr_t *ip;

            src_ip[0] = 0;
            ip = GET_SRC_IP(p);
            inet_ntop(sfaddr_family(ip), (void *)sfaddr_get_ptr(ip), src_ip, sizeof(src_ip));
            dst_ip[0] = 0;
            ip = GET_DST_IP(p);
            inet_ntop(sfaddr_family(ip), (void *)sfaddr_get_ptr(ip), dst_ip, sizeof(dst_ip));
            fprintf(SF_DEBUG_FILE, "AppId Http Callback Session %s-%u -> %s-%u %d\n", src_ip,
                    (unsigned)p->src_port, dst_ip, (unsigned)p->dst_port, IsTCP(p) ? IPPROTO_TCP:IPPROTO_UDP);
    }
#endif

    if (!session->hsession)
    {
        if (!(session->hsession = calloc(1, sizeof(*session->hsession))))
            DynamicPreprocessorFatalMessage("Could not allocate httpSession data");
    }

    if (direction == APP_ID_FROM_INITIATOR)
    {
        if (headers->host.start)
        {
            free(session->hsession->host);
            session->hsession->host = strndup((char *)headers->host.start, headers->host.len);
            session->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;

            if (headers->url.start)
            {
                free(session->hsession->url);
                session->hsession->url = malloc(sizeof(HTTP_PREFIX) + headers->host.len + headers->url.len);
                if (session->hsession->url)
                {
                    strcpy(session->hsession->url, HTTP_PREFIX);
                    strncat(session->hsession->url, (char *)headers->host.start, headers->host.len);
                    strncat(session->hsession->url, (char *)headers->url.start, headers->url.len);
                    session->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
                }
            }
        }
        if (headers->userAgent.start)
        {
            free(session->hsession->useragent);
            session->hsession->useragent  = strndup((char *)headers->userAgent.start, headers->userAgent.len);
            session->scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        }
        if (headers->referer.start)
        {
            free(session->hsession->referer);
            session->hsession->referer  = strndup((char *)headers->referer.start, headers->referer.len);

        }
        if (headers->via.start)
        {
            free(session->hsession->via);
            session->hsession->via  = strndup((char *)headers->via.start, headers->via.len);
            session->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }

    }
    else
    {
        if (headers->via.start)
        {
            free(session->hsession->via);
            session->hsession->via  = strndup((char *)headers->via.start, headers->via.len);
            session->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        if (headers->contentType.start)
        {
            free(session->hsession->content_type);
            session->hsession->content_type  = strndup((char *)headers->contentType.start, headers->contentType.len);
        }
        if (headers->responseCode.start)
        {
            long responseCodeNum;
            responseCodeNum = strtoul((char *)headers->responseCode.start, NULL, 10);
            if (responseCodeNum > 0 && responseCodeNum < 700)
            {
                free(session->hsession->response_code);
                session->hsession->response_code  = strndup((char *)headers->responseCode.start, headers->responseCode.len);
            }
        }
    }
    processHTTPPacket(p, session, direction, headers, pConfig);

    setAppIdExtFlag(session, APPID_SESSION_SERVICE_DETECTED);
    setAppIdExtFlag(session, APPID_SESSION_HTTP_SESSION);

    _dpd.streamAPI->set_application_id(p->stream_session, pickServiceAppId(session), pickClientAppId(session), pickPayloadId(session), pickMiscAppId(session));
}

static inline void ExamineRtmpMetadata(tAppIdData *appIdSession)
{
    tAppId serviceAppId = 0;
    tAppId clientAppId = 0;
    tAppId payloadAppId = 0;
    tAppId referredPayloadAppId = 0;
    char *version = NULL;
    httpSession *hsession;
    tAppIdConfig *pConfig = appIdActiveConfigGet();

    if (!appIdSession->hsession)
    {
        if (!(appIdSession->hsession = calloc(1, sizeof(*appIdSession->hsession))))
            DynamicPreprocessorFatalMessage("Could not allocate httpSession data");
    }

    hsession = appIdSession->hsession;

    if (hsession->url)
    {
        if (((getAppIdFromUrl(NULL, hsession->url, &version,
                            hsession->referer, &clientAppId, &serviceAppId,
                            &payloadAppId, &referredPayloadAppId, 1, &pConfig->detectorHttpConfig)) ||
                    (getAppIdFromUrl(NULL, hsession->url, &version,
                                     hsession->referer, &clientAppId, &serviceAppId,
                                     &payloadAppId, &referredPayloadAppId, 0, &pConfig->detectorHttpConfig))) == 1)

        {
            /* do not overwrite a previously-set client or service */
            if (appIdSession->clientAppId <= APP_ID_NONE)
                setClientAppIdData(appIdSession, clientAppId, NULL);
            if (appIdSession->serviceAppId <= APP_ID_NONE)
                setServiceAppIdData(appIdSession, serviceAppId, NULL, NULL);

            /* DO overwrite a previously-set payload */
            setPayloadAppIdData(appIdSession, payloadAppId, NULL);
            setReferredPayloadAppIdData(appIdSession, referredPayloadAppId);
        }
    }
}

void checkSandboxDetection(tAppId appId)
{
    AppInfoTableEntry *entry;
    tAppIdConfig *pConfig = appIdActiveConfigGet();

    if (appidStaticConfig.instance_id && pConfig)
    {
        entry = appInfoEntryGet(appId, pConfig);
        if (entry && entry->flags & APPINFO_FLAG_ACTIVE)
        {
            fprintf(SF_DEBUG_FILE, "add service\n");
            fprintf(SF_DEBUG_FILE, "Detected AppId %d\n", entry->appId);
        }
    }
}
