/******************************************************************************
 * Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2009-2013 Sourcefire, Inc.
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
 ******************************************************************************/

#ifndef __APPID_API_H__
#define __APPID_API_H__

#include "stdint.h"
#include "stdbool.h"
#include "ipv6_port.h"

struct AppIdData;

typedef int32_t tAppId;

typedef enum
{
    APPID_SESSION_RESPONDER_MONITORED   = (1 << 0),
    APPID_SESSION_INITIATOR_MONITORED   = (1 << 1),
    APPID_SESSION_SPECIAL_MONITORED     = (1 << 2),
    APPID_SESSION_INITIATOR_SEEN        = (1 << 3),
    APPID_SESSION_RESPONDER_SEEN        = (1 << 4),
    APPID_SESSION_DISCOVER_USER         = (1 << 5),
    APPID_SESSION_HAS_DHCP_FP           = (1 << 6),
    APPID_SESSION_HAS_DHCP_INFO         = (1 << 7),
    APPID_SESSION_HAS_SMB_INFO          = (1 << 8),
    APPID_SESSION_MID                   = (1 << 9),
    APPID_SESSION_OOO                   = (1 << 10),
    APPID_SESSION_SYN_RST               = (1 << 11),

    /**Service missed the first UDP packet in a flow. This causes detectors to see traffic in reverse direction.
     * Detectors should set this flag by verifying that packet from initiator is indeed a packet from responder.
     * Setting this flag without this check will cause RNA to not try other detectors in some cases (see bug 77551).*/
    APPID_SESSION_UDP_REVERSED          = (1 << 12),
    APPID_SESSION_HTTP_SESSION          = (1 << 13),

    /**Service protocol was detected */
    APPID_SESSION_SERVICE_DETECTED      = (1 << 14),

    /**Finsihed with client app detection */
    APPID_SESSION_CLIENT_DETECTED       = (1 << 15),
    /**Flow is a data connection not a service */
    APPID_SESSION_NOT_A_SERVICE         = (1 << 16),

    APPID_SESSION_DECRYPTED             = (1 << 17),
    APPID_SESSION_SERVICE_DELETED       = (1 << 18),

    //The following attributes are references only with appId
    /**Continue calling the routine after the service has been identified. */
    APPID_SESSION_CONTINUE              = (1 << 19),
    /**Call service detection even if the host does not exist */
    APPID_SESSION_IGNORE_HOST           = (1 << 20),
    /**Service protocol had incompatible client data */
    APPID_SESSION_INCOMPATIBLE          = (1 << 21),
    /**we are ready to see out of network Server packets */
    APPID_SESSION_CLIENT_GETS_SERVER_PACKETS = (1 << 22),

    APPID_SESSION_DISCOVER_APP          = (1 << 23),

    APPID_SESSION_PORT_SERVICE_DONE     = (1 << 24),
    APPID_SESSION_ADDITIONAL_PACKET     = (1 << 25),
    APPID_SESSION_RESPONDER_CHECKED     = (1 << 26),
    APPID_SESSION_INITIATOR_CHECKED     = (1 << 27),
    APPID_SESSION_SSL_SESSION           = (1 << 28),
    APPID_SESSION_LOGIN_SUCCEEDED       = (1 << 29),

    APPID_SESSION_SPDY_SESSION          = (1 << 30),
    APPID_SESSION_ENCRYPTED             = (1 << 31),
} APPID_SESSION_ATTRIBUTES;


typedef enum
{
    APPID_FLOW_TYPE_IGNORE,
    APPID_FLOW_TYPE_NORMAL,
    APPID_FLOW_TYPE_TMP
} APPID_FLOW_TYPE;

typedef struct _RNAServiceSubtype
{
    struct _RNAServiceSubtype *next;
    const char *service;
    const char *vendor;
    const char *version;
} RNAServiceSubtype;

#define DHCP_OP55_MAX_SIZE  64
#define DHCP_OP60_MAX_SIZE  64

typedef struct _DHCP_FP_DATA
{
    struct _DHCP_FP_DATA *next;
    unsigned op55_len;
    unsigned op60_len;
    uint8_t op55[DHCP_OP55_MAX_SIZE];
    uint8_t op60[DHCP_OP60_MAX_SIZE];
    uint8_t mac[6];
} DhcpFPData;

typedef struct _DHCPInfo
{
    struct _DHCPInfo *next;
    uint32_t ipAddr;
    uint8_t  macAddr[6];
    uint32_t subnetmask;
    uint32_t leaseSecs;
    uint32_t router;
} DHCPInfo;

typedef struct _FpSMBData
{
    struct _FpSMBData *next;
    unsigned major;
    unsigned minor;
    uint32_t flags;
} FpSMBData;

//maximum number of appIds replicated for a flow/session
#define APPID_HA_SESSION_APP_NUM_MAX 8

typedef struct _AppIdSessionHA
{
    uint16_t flags;
    tAppId appId[APPID_HA_SESSION_APP_NUM_MAX];
} AppIdSessionHA;

typedef enum
{
    NOT_A_SEARCH_ENGINE,
    SUPPORTED_SEARCH_ENGINE,
    UNSUPPORTED_SEARCH_ENGINE,
} SEARCH_SUPPORT_TYPE;

/*******************************************************************************
 * AppId API
 ******************************************************************************/
struct AppIdApi
{
    const char * (*getApplicationName)(int32_t appId);
    tAppId (*getApplicationId)(const char *appName);

    tAppId (*getServiceAppId)(struct AppIdData *session);
    tAppId (*getPortServiceAppId)(struct AppIdData *session);
    tAppId (*getOnlyServiceAppId)(struct AppIdData *session);
    tAppId (*getMiscAppId)(struct AppIdData *session);
    tAppId (*getClientAppId)(struct AppIdData *session);
    tAppId (*getPayloadAppId)(struct AppIdData *session);
    tAppId (*getReferredAppId)(struct AppIdData *session);
    tAppId (*getFwServiceAppId)(struct AppIdData *session);
    tAppId (*getFwMiscAppId)(struct AppIdData *session);
    tAppId (*getFwClientAppId)(struct AppIdData *session);
    tAppId (*getFwPayloadAppId)(struct AppIdData *session);
    tAppId (*getFwReferredAppId)(struct AppIdData *session);

    bool (*isSessionSslDecrypted)(struct AppIdData *session);
    bool (*isAppIdInspectingSession)(struct AppIdData *session);
    bool (*isAppIdAvailable)(struct AppIdData *session);

    char* (*getUserName)(struct AppIdData *session, tAppId *service, bool *isLoginSuccessful);
    char* (*getClientVersion)(struct AppIdData *session);

    unsigned (*getAppIdSessionAttribute)(struct AppIdData *session, unsigned int flag);

    APPID_FLOW_TYPE (*getFlowType)(struct AppIdData *session);
    void (*getServiceInfo)(struct AppIdData *session, char **serviceVendor, char **serviceVersion, RNAServiceSubtype **subtype);
    short (*getServicePort)(struct AppIdData *session);
    sfaddr_t* (*getServiceIp)(struct AppIdData *session);

    char* (*getHttpUserAgent)(struct AppIdData *session);
    char* (*getHttpHost)(struct AppIdData *session);
    char* (*getHttpUrl)(struct AppIdData *session);
    char* (*getHttpReferer)(struct AppIdData *session);
    char* (*getHttpNewUrl)(struct AppIdData *session);
    char* (*getHttpUri)(struct AppIdData *session);
    char* (*getHttpResponseCode)(struct AppIdData *session);
    char* (*getHttpCookie)(struct AppIdData *session);
    char* (*getHttpNewCookie)(struct AppIdData *session);
    char* (*getHttpContentType)(struct AppIdData *session);
    char* (*getHttpLocation)(struct AppIdData *session);
    char* (*getHttpBody)(struct AppIdData *session);
    char* (*getHttpReqBody)(struct AppIdData *session);
    uint16_t (*getHttpUriOffset)(struct AppIdData *session);
    uint16_t (*getHttpUriEndOffset)(struct AppIdData *session);
    uint16_t (*getHttpCookieOffset)(struct AppIdData *session);
    uint16_t (*getHttpCookieEndOffset)(struct AppIdData *session);
    SEARCH_SUPPORT_TYPE (*getHttpSearch)(struct AppIdData *session);

    char* (*getTlsHost)(struct AppIdData *session);

    DhcpFPData* (*getDhcpFpData)(struct AppIdData *session);
    void (*freeDhcpFpData)(struct AppIdData *session, DhcpFPData *data);
    DHCPInfo* (*getDhcpInfo)(struct AppIdData *session);
    void (*freeDhcpInfo)(struct AppIdData *session, DHCPInfo *data);
    FpSMBData* (*getSmbFpData)(struct AppIdData *session);
    void (*freeSmbFpData)(struct AppIdData *session, FpSMBData *data);
    char* (*getNetbiosName)(struct AppIdData *session);
    uint32_t (*produceHAState)(void *lwssn, uint8_t *buf);
    uint32_t (*consumeHAState)(void *lwssn, const uint8_t *buf, uint8_t length, uint8_t proto, sfaddr_t* ip);
    struct AppIdData * (*getAppIdData)(void *lwssn);

    char* (*getDNSQuery)(struct AppIdData *appIdData, uint8_t *query_len);
    uint16_t (*getDNSQueryoffset)(struct AppIdData *appIdData);
    uint16_t (*getDNSRecordType)(struct AppIdData *appIdData);
    uint8_t (*getDNSResponseType)(struct AppIdData *appIdData);
    uint32_t (*getDNSTTL)(struct AppIdData *appIdData);
};

/* For access when including header */
extern struct AppIdApi appIdApi;


#endif  /* __APPID_API_H__ */

