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


#ifndef __SERVICE_BASE_H__
#define __SERVICE_BASE_H__

#include "appIdApi.h"
#include "service_api.h"
#include "commonAppMatcher.h"
#include "flow.h"
#include "serviceConfig.h"
#include "appIdConfig.h"
struct _SERVICE_MATCH;

void CleanupServices(tAppIdConfig *pConfig);
void ReconfigureServices(tAppIdConfig *pConfig);
void UnconfigureServices(tAppIdConfig *pConfig);
void ServiceInit(tAppIdConfig *pConfig);
void ServiceFinalize(tAppIdConfig *pConfig);
void FailInProcessService(tAppIdData *flowp, const tAppIdConfig *pConfig);
int LoadServiceModules(const char **dir_list, uint32_t instance_id, tAppIdConfig *pConfig);

/**
 * \brief Reload C service modules
 *
 * This function is called during reload/reconfiguration. It registers service ports in the given
 * AppId configuration. This function also takes care of services associated with detector modules.
 *
 * @param pConfig - AppId config in which services' ports get registered
 * @return 0 on success, -1 on failure
 */
int ReloadServiceModules(tAppIdConfig *pConfig);
int serviceLoadCallback(void *symbol);
int serviceLoadForConfigCallback(void *symbol, tAppIdConfig *pConfig);
int ServiceAddPort(RNAServiceValidationPort *pp, tRNAServiceValidationModule *svm,
                   struct _Detector* userdata, tAppIdConfig *pConfig);
void ServiceRemovePorts(RNAServiceValidationFCN validate, struct _Detector* userdata, tAppIdConfig *pConfig);
void ServiceRegisterPatternDetector(RNAServiceValidationFCN fcn,
                                    u_int8_t proto, const u_int8_t *pattern, unsigned size,
                                    int position, struct _Detector *userdata,
                                    const char *name);
int AppIdDiscoverService(SFSnortPacket *p, int direction, tAppIdData *rnaData, const tAppIdConfig *pConfig);
tAppId getPortServiceId(uint8_t proto, uint16_t port, const tAppIdConfig *pConfig);

void AppIdFreeServiceIDState(AppIdServiceIDState *id_state);

int AppIdServiceAddService(tAppIdData*flow, const SFSnortPacket *pkt, int dir,
                           const tRNAServiceElement *svc_element,
                           tAppId appId, const char *vendor, const char *version,
                           const RNAServiceSubtype *subtype);
int AppIdServiceAddServiceSubtype(tAppIdData*flow, const SFSnortPacket *pkt, int dir,
                                  const tRNAServiceElement *svc_element,
                                  tAppId appId, const char *vendor, const char *version,
                                  RNAServiceSubtype *subtype);
int AppIdServiceInProcess(tAppIdData*flow, const SFSnortPacket *pkt, int dir,
                          const tRNAServiceElement *svc_element);
int AppIdServiceIncompatibleData(tAppIdData*flow, const SFSnortPacket *pkt, int dir,
                                 const tRNAServiceElement *svc_element, unsigned flow_data_index, const tAppIdConfig *pConfig);
int AppIdServiceFailService(tAppIdData*flow, const SFSnortPacket *pkt, int dir,
                            const tRNAServiceElement *svc_element, unsigned flow_data_index, const tAppIdConfig *pConfig);
int AddFTPServiceState(tAppIdData *fp);
void AppIdFreeDhcpInfo(DHCPInfo *dd);
void AppIdFreeSMBData(FpSMBData *sd);
void AppIdFreeDhcpData(DhcpFPData *dd);

void dumpPorts(FILE *stream, const tAppIdConfig *pConfig);

const tRNAServiceElement *ServiceGetServiceElement(RNAServiceValidationFCN fcn, struct _Detector *userdata, tAppIdConfig *pConfig);

extern tRNAServiceValidationModule *active_service_list;

extern uint32_t app_id_instance_id;
void cleanupFreeServiceMatch(void);
void AppIdFreeServiceMatchList(struct _SERVICE_MATCH* sm);

static inline bool compareServiceElements(const tRNAServiceElement *first, const tRNAServiceElement *second)
{
    if (first == second)
        return 0;
    if (first == NULL || second == NULL)
        return 1;
    return (first->validate != second->validate || first->userdata != second->userdata);
}

static inline uint32_t AppIdServiceDetectionLevel(tAppIdData * session)
{
    if (getAppIdExtFlag(session, APPID_SESSION_DECRYPTED)) return 1;
    return 0;
}

#endif /* __SERVICE_BASE_H__ */

