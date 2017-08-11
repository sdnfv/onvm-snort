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

#include "appIdApi.h"
#include "fw_appid.h"
#include "thirdparty_appid_api.h"

#define SSL_WHITELIST_PKT_LIMIT 20

tAppId getServiceAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return pickServiceAppId(appIdData);
    return APP_ID_NONE;
}
tAppId getOnlyServiceAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return pickOnlyServiceAppId(appIdData);
    return APP_ID_NONE;
}
tAppId getMiscAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return pickMiscAppId(appIdData);
    return APP_ID_NONE;
}
tAppId getClientAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return pickClientAppId(appIdData);
    return APP_ID_NONE;
}
tAppId getPayloadAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return pickPayloadId(appIdData);
    return APP_ID_NONE;
}
tAppId getReferredAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return pickReferredPayloadId(appIdData);
    return APP_ID_NONE;
}
tAppId getFwServiceAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return fwPickServiceAppId(appIdData);
    return APP_ID_NONE;
}
tAppId getFwMiscAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return fwPickMiscAppId(appIdData);
    return APP_ID_NONE;
}
tAppId getFwClientAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return fwPickClientAppId(appIdData);
    return APP_ID_NONE;
}
tAppId getFwPayloadAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return fwPickPayloadAppId(appIdData);
    return APP_ID_NONE;
}
tAppId getFwReferredAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return fwPickReferredPayloadAppId(appIdData);
    return APP_ID_NONE;
}
bool isSessionSslDecrypted(struct AppIdData *appIdData)
{
    if (appIdData)
        return isFwSessionSslDecrypted(appIdData);
    return false;
}

struct AppIdData * getAppIdData(void* lwssn)
{
    tAppIdData *appIdData = _dpd.sessionAPI->get_application_data(lwssn, PP_APP_ID);
    return (appIdData && appIdData->common.fsf_type.flow_type == APPID_SESSION_TYPE_NORMAL)? appIdData : NULL;
}

bool IsAppIdInspectingSession(struct AppIdData *appIdSession)
{
    if (appIdSession && appIdSession->common.fsf_type.flow_type == APPID_SESSION_TYPE_NORMAL)
    {
        if (!TPIsAppIdDone(appIdSession->tpsession) || getAppIdExtFlag(appIdSession, APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE)
             || (getAppIdExtFlag(appIdSession, APPID_SESSION_ENCRYPTED) && (getAppIdExtFlag(appIdSession, APPID_SESSION_DECRYPTED) || appIdSession->session_packet_count < SSL_WHITELIST_PKT_LIMIT))
             || appIdSession->rnaServiceState != RNA_STATE_FINISHED)
        {
            return true;
        }
        if (appIdSession->rnaClientState != RNA_STATE_FINISHED &&
            (!getAppIdExtFlag(appIdSession, APPID_SESSION_CLIENT_DETECTED) ||
             (appIdSession->rnaServiceState != RNA_STATE_STATEFUL && getAppIdExtFlag(appIdSession, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))))
        {
            return true;
        }
        if (appIdSession->tpAppId == APP_ID_SSH && appIdSession->payloadAppId != APP_ID_SFTP && appIdSession->session_packet_count < MAX_SFTP_PACKET_COUNT)
        {
            return true;
        }
    }
    return false;
}
char* getUserName(struct AppIdData *appIdData, tAppId *service, bool *isLoginSuccessful)
{
    char *userName = NULL;
    if (appIdData)
    {
        userName = appIdData->username;
        *service = appIdData->usernameService;
        *isLoginSuccessful = getAppIdExtFlag(appIdData, APPID_SESSION_LOGIN_SUCCEEDED);
        appIdData->username = NULL; //transfer ownership to caller.
        return userName;
    }
    return NULL;
}
bool isAppIdAvailable(struct AppIdData *appIdData)
{
    return appIdData? TPIsAppIdAvailable(appIdData->tpsession): false;
}
char* getClientVersion(struct AppIdData *appIdData)
{
    return appIdData? appIdData->clientVersion: NULL;
}
unsigned  getAppIdSessionAttribute(struct AppIdData *appIdData, unsigned flags)
{
    return appIdData? getAppIdExtFlag(appIdData,flags): 0;
}

APPID_FLOW_TYPE getFlowType(struct AppIdData *appIdData)
{
    return appIdData ? appIdData->common.fsf_type.flow_type: APPID_FLOW_TYPE_IGNORE;
}

void getServiceInfo(struct AppIdData *appIdData, char **serviceVendor, char **serviceVersion, RNAServiceSubtype **serviceSubtype)
{
    if (appIdData)
    {
        *serviceVendor = appIdData->serviceVendor;
        *serviceVersion = appIdData->serviceVersion;
        *serviceSubtype = appIdData->subtype;
    }
    else
    {
        *serviceVendor = NULL;
        *serviceVersion = NULL;
        *serviceSubtype = NULL;
    }
}
short getServicePort(struct AppIdData *appIdData)
{
    if (appIdData)
        return appIdData->service_port;
    return 0;
}
char* getHttpUserAgent(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->useragent;
    return NULL;
}
char* getHttpHost(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->host;
    return NULL;
}
char* getHttpUrl(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->url;
    return NULL;
}
char* getHttpReferer(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->referer;
    return NULL;
}
char* getHttpNewUrl(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->new_url;
    return NULL;
}
char* getHttpUri(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->uri;
    return NULL;
}
char* getHttpResponseCode(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->response_code;
    return NULL;
}
char* getHttpCookie(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->cookie;
    return NULL;
}
char* getHttpNewCookie(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->new_cookie;
    return NULL;
}
char* getHttpContentType(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->content_type;
    return NULL;
}
char* getHttpLocation(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->location;
    return NULL;
}
char* getHttpBody(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->body;
    return NULL;
}
char* getHttpReqBody(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->req_body;
    return NULL;
}
uint16_t getHttpUriOffset(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->uriOffset;
    return 0;
}
uint16_t getHttpUriEndOffset(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->uriEndOffset;
    return 0;
}
uint16_t getHttpCookieOffset(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->cookieOffset;
    return 0;
}
uint16_t getHttpCookieEndOffset(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->cookieEndOffset;
    return 0;
}
SEARCH_SUPPORT_TYPE getHttpSearch(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->hsession)
        return appIdData->hsession->search_support_type;
    return NOT_A_SEARCH_ENGINE;
}
char* getTlsHost(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->tsession)
        return appIdData->tsession->tls_host;
    return NULL;
}
tAppId getPortServiceAppId(struct AppIdData *appIdData)
{
    if (appIdData)
        return appIdData->portServiceAppId;
    return APP_ID_NONE;
}
sfaddr_t* getServiceIp(struct AppIdData *appIdData)
{
    if (appIdData)
        return &appIdData->service_ip;
    return NULL;
}
DhcpFPData* getDhcpFpData(struct AppIdData *appIdData)
{
    DhcpFPData *data;
    if (appIdData && getAppIdExtFlag(appIdData, APPID_SESSION_HAS_DHCP_FP))
    {
        data = AppIdFlowdataRemove(appIdData, APPID_SESSION_DATA_DHCP_FP_DATA);
        return data;
    }
    return NULL;
}
void freeDhcpFpData(struct AppIdData *appIdData, DhcpFPData *data)
{
    if (appIdData)
    {
        clearAppIdExtFlag(appIdData, APPID_SESSION_HAS_DHCP_FP);
        AppIdFreeDhcpData(data);
    }
}

DHCPInfo* getDhcpInfo(struct AppIdData *appIdData)
{
    DHCPInfo *data;
    if (appIdData && getAppIdExtFlag(appIdData, APPID_SESSION_HAS_DHCP_INFO))
    {
        data = AppIdFlowdataRemove(appIdData, APPID_SESSION_DATA_DHCP_INFO);
        return data;
    }
    return NULL;
}

void freeDhcpInfo(struct AppIdData *appIdData, DHCPInfo *data)
{
    if (appIdData)
    {
        clearAppIdExtFlag(appIdData, APPID_SESSION_HAS_DHCP_INFO);
        AppIdFreeDhcpInfo(data);
    }
}

FpSMBData* getSmbFpData(struct AppIdData *appIdData)
{
    FpSMBData *data;
    if (appIdData && getAppIdExtFlag(appIdData, APPID_SESSION_HAS_SMB_INFO))
    {
        data = AppIdFlowdataRemove(appIdData, APPID_SESSION_DATA_SMB_DATA);
        return data;
    }
    return NULL;
}

void freeSmbFpData(struct AppIdData *appIdData, FpSMBData *data)
{
    if (appIdData)
    {
        clearAppIdExtFlag(appIdData, APPID_SESSION_HAS_SMB_INFO);
        AppIdFreeSMBData(data);
    }
}

char* getNetbiosName(struct AppIdData *appIdData)
{
    if (appIdData)
    {
        char *netbiosName = appIdData->netbios_name;
        appIdData->netbios_name = NULL; //transfer ownership to caller.
        return netbiosName;
    }
    return NULL;
}

#define APPID_HA_FLAGS_APP (1<<0)
#define APPID_HA_FLAGS_TP_DONE (1<<1)
#define APPID_HA_FLAGS_SVC_DONE (1<<2)
#define APPID_HA_FLAGS_HTTP (1<<3)

uint32_t produceHAState(void *lwssn, uint8_t *buf)
{
    AppIdSessionHA *appHA = (AppIdSessionHA *)buf;
    struct AppIdData *appIdData = _dpd.sessionAPI->get_application_data(lwssn, PP_APP_ID);
    if (appIdData && _dpd.appIdApi->getFlowType(appIdData) != APPID_FLOW_TYPE_NORMAL)
        appIdData = NULL;
    if (appIdData)
    {

        appHA->flags = APPID_HA_FLAGS_APP;
        if (TPIsAppIdAvailable(appIdData->tpsession))
            appHA->flags |= APPID_HA_FLAGS_TP_DONE;
        if (getAppIdExtFlag(appIdData, APPID_SESSION_SERVICE_DETECTED))
            appHA->flags |= APPID_HA_FLAGS_SVC_DONE;
        if (getAppIdExtFlag(appIdData, APPID_SESSION_HTTP_SESSION))
            appHA->flags |= APPID_HA_FLAGS_HTTP;
        appHA->appId[0] = appIdData->tpAppId;
        appHA->appId[1] = appIdData->serviceAppId;
        appHA->appId[2] = appIdData->clientServiceAppId;
        appHA->appId[3] = appIdData->portServiceAppId;
        appHA->appId[4] = appIdData->payloadAppId;
        appHA->appId[5] = appIdData->tpPayloadAppId;
        appHA->appId[6] = appIdData->clientAppId;
        appHA->appId[7] = appIdData->miscAppId;
    }
    else
    {
        memset(appHA->appId, 0, sizeof(appHA->appId));
    }
    return sizeof(*appHA);
}
uint32_t consumeHAState(void *lwssn, const uint8_t *buf, uint8_t length, uint8_t proto, sfaddr_t *ip)
{
    AppIdSessionHA *appHA = (AppIdSessionHA *)buf;
    if (appHA->flags & APPID_HA_FLAGS_APP)
    {
        struct AppIdData *appIdData = (tAppIdData*)_dpd.sessionAPI->get_application_data(lwssn, PP_APP_ID);
        if (!appIdData)
        {
            appIdData = appSharedDataAlloc(proto, ip);
            _dpd.sessionAPI->set_application_data(lwssn, PP_APP_ID, appIdData, (void (*)(void *))appSharedDataDelete);
            if (appIdData->serviceAppId == APP_ID_FTP_CONTROL)
            {
                setAppIdExtFlag(appIdData, APPID_SESSION_CLIENT_DETECTED | APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
                if (!AddFTPServiceState(appIdData))
                {
                    setAppIdExtFlag(appIdData, APPID_SESSION_CONTINUE);
                }
                appIdData->rnaServiceState = RNA_STATE_STATEFUL;
            }
            else
                appIdData->rnaServiceState = RNA_STATE_FINISHED;
            appIdData->rnaClientState = RNA_STATE_FINISHED;
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_state_set(appIdData->tpsession, TP_STATE_HA);
        }

        if (appHA->flags & APPID_HA_FLAGS_TP_DONE && thirdparty_appid_module)
        {
                thirdparty_appid_module->session_state_set(appIdData->tpsession, TP_STATE_TERMINATED);
                setAppIdIntFlag(appIdData, APPID_SESSION_APP_NO_TPI);
        }
        if (appHA->flags & APPID_HA_FLAGS_SVC_DONE)
            setAppIdExtFlag(appIdData, APPID_SESSION_SERVICE_DETECTED);
        if (appHA->flags & APPID_HA_FLAGS_HTTP)
            setAppIdExtFlag(appIdData, APPID_SESSION_HTTP_SESSION);

        appIdData->tpAppId = appHA->appId[0];
        appIdData->serviceAppId = appHA->appId[1];
        appIdData->clientServiceAppId = appHA->appId[2];
        appIdData->portServiceAppId = appHA->appId[3];
        appIdData->payloadAppId = appHA->appId[4];
        appIdData->tpPayloadAppId = appHA->appId[5];
        appIdData->clientAppId = appHA->appId[6];
        appIdData->miscAppId = appHA->appId[7];

    }
    return sizeof(*appHA);
}

char* getDNSQuery(struct AppIdData *appIdData, uint8_t *query_len)
{
    if (appIdData && appIdData->dsession)
    {
        if (query_len)
            if (appIdData->dsession->host)
                *query_len = appIdData->dsession->host_len;
            else
                *query_len = 0;
        return appIdData->dsession->host;
    }
    if (query_len)
        *query_len = 0;
    return NULL;
}
uint16_t getDNSQueryoffset(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->dsession)
        return appIdData->dsession->host_offset;
    return 0;
}
uint16_t getDNSRecordType(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->dsession)
        return appIdData->dsession->record_type;
    return 0;
}
uint8_t getDNSResponseType(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->dsession)
        return appIdData->dsession->response_type;
    return 0;
}
uint32_t getDNSTTL(struct AppIdData *appIdData)
{
    if (appIdData && appIdData->dsession)
        return appIdData->dsession->ttl;
    return 0;
}

static struct AppIdApi appIdDispatchTable = {
    appGetAppName,
    appGetAppId,

    getServiceAppId,
    getPortServiceAppId,
    getOnlyServiceAppId,
    getMiscAppId,
    getClientAppId,
    getPayloadAppId,
    getReferredAppId,
    getFwServiceAppId,
    getFwMiscAppId,
    getFwClientAppId,
    getFwPayloadAppId,
    getFwReferredAppId,

    isSessionSslDecrypted,
    IsAppIdInspectingSession,
    isAppIdAvailable,

    getUserName,
    getClientVersion,

    getAppIdSessionAttribute,

    getFlowType,
    getServiceInfo,
    getServicePort,
    getServiceIp,

    getHttpUserAgent,
    getHttpHost,
    getHttpUrl,
    getHttpReferer,
    getHttpNewUrl,
    getHttpUri,
    getHttpResponseCode,
    getHttpCookie,
    getHttpNewCookie,
    getHttpContentType,
    getHttpLocation,
    getHttpBody,
    getHttpReqBody,
    getHttpUriOffset,
    getHttpUriEndOffset,
    getHttpCookieOffset,
    getHttpCookieEndOffset,
    getHttpSearch,

    getTlsHost,

    getDhcpFpData,
    freeDhcpFpData,
    getDhcpInfo,
    freeDhcpInfo,
    getSmbFpData,
    freeSmbFpData,
    getNetbiosName,
    produceHAState,
    consumeHAState,

    getAppIdData,

    getDNSQuery,
    getDNSQueryoffset,
    getDNSRecordType,
    getDNSResponseType,
    getDNSTTL,
};

void appIdApiInit(struct AppIdApi *api)
{
    *api = appIdDispatchTable;
}
