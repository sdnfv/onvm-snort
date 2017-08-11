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
#include <strings.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>

#include "sf_dynamic_preprocessor.h"
#include "appIdConfig.h"
#include "common_util.h"

#define APP_ID_MEMCAP_DEFAULT       (256*1024*1024ULL)
#define APP_ID_MEMCAP_UPPER_BOUND   (3*1024*1024*1024ULL)
#define APP_ID_MEMCAP_LOWER_BOUND   (32*1024*1024ULL)

#define DEFAULT_APPID_DETECTOR_PATH "/usr/local/etc/appid"

void appIdConfigParse(char *args)
{
    char **toks;
    int num_toks;
    int i;
    char **stoks;
    int s_toks;
    char *endPtr;

    if ((args == NULL) || (strlen(args) == 0))
        return;

    memset (&appidStaticConfig, 0, sizeof(appidStaticConfig));

    toks = _dpd.tokenSplit(args, ",", 0, &num_toks, 0);
    i = 0;

    for (i = 0; i < num_toks; i++)
    {
        stoks = _dpd.tokenSplit(toks[i], " ", 2, &s_toks, 0);

        if (s_toks == 0)
        {
            _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Missing AppId configuration");
        }

        if(!strcasecmp(stoks[0], "conf"))
        {
            if (!stoks[1] || strlen(stoks[1]) >= sizeof(appidStaticConfig.conf_file))
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid rna_conf");
            }

            snprintf(appidStaticConfig.conf_file, sizeof(appidStaticConfig.conf_file), "%s", stoks[1]);
        }
        else if(!strcasecmp(stoks[0], "debug"))
        {
            if (!stoks[1])
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid debug");
            }
            if (!strcasecmp(stoks[1], "yes"))
                appidStaticConfig.app_id_debug = 1;
        }
        else if(!strcasecmp(stoks[0], "dump_ports"))
        {
            if (stoks[1])
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid dump ports specified");
            }
            appidStaticConfig.app_id_dump_ports = 1;
        }
        else if(!strcasecmp(stoks[0], "memcap"))
        {
            if (!stoks[1])
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid memcap");
            }

            appidStaticConfig.memcap = strtoul(stoks[1], &endPtr, 10);
            if (!*stoks[1] || *endPtr)
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid memcap");
            }

            if (appidStaticConfig.memcap == 0)
                appidStaticConfig.memcap = APP_ID_MEMCAP_LOWER_BOUND;
        }
        else if(!strcasecmp(stoks[0], "app_stats_filename"))
        {
            if (!stoks[1] || strlen(stoks[1]) >= sizeof(appidStaticConfig.app_stats_filename))
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid stats_filename");
            }

            snprintf(appidStaticConfig.app_stats_filename, sizeof(appidStaticConfig.app_stats_filename), "%s", stoks[1]);
        }
        else if(!strcasecmp(stoks[0], "app_stats_period"))
        {
            if (!stoks[1])
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid app_stats_period");
            }

            appidStaticConfig.app_stats_period = strtoul(stoks[1], &endPtr, 10);
            if (!*stoks[1] || *endPtr)
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid app_stats_period");
            }
        }
        else if(!strcasecmp(stoks[0], "app_stats_rollover_size"))
        {
            if (!stoks[1])
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid app_stats_rollover_size");
            }

            appidStaticConfig.app_stats_rollover_size = strtoul(stoks[1], &endPtr, 10);
            if (!*stoks[1] || *endPtr)
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid app_stats_rollover_size");
            }
        }
        else if(!strcasecmp(stoks[0], "app_stats_rollover_time"))
        {
            if (!stoks[1])
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid app_stats_rollover_time");
            }

            appidStaticConfig.app_stats_rollover_time = strtoul(stoks[1], &endPtr, 10);
            if (!*stoks[1] || *endPtr)
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid app_stats_rollover_time");
            }
        }
        else if(!strcasecmp(stoks[0], "app_detector_dir"))
        {
            if (!stoks[1] || strlen(stoks[1]) >= sizeof(appidStaticConfig.app_id_detector_path))
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid app_detector_dir");
            }

            snprintf(appidStaticConfig.app_id_detector_path, sizeof(appidStaticConfig.app_id_detector_path), "%s", stoks[1]);
        }
       else if(!strcasecmp(stoks[0], "instance_id"))
        {
            if (!stoks[1])
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid instance id");
            }
            appidStaticConfig.instance_id = strtoul(stoks[1], &endPtr, 10);
            if (!*stoks[1] || *endPtr)
            {
                _dpd.fatalMsg("Invalid instance id specified");
            }
        }
        else if(!strcasecmp(stoks[0], "thirdparty_appid_dir"))
        {
            if (appidStaticConfig.appid_thirdparty_dir)
            {
                free((void *)appidStaticConfig.appid_thirdparty_dir);
                appidStaticConfig.appid_thirdparty_dir = NULL;
            }
            if (!stoks[1])
            {
                _dpd.fatalMsg("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), "Invalid ThirdpartyDirectory");
            }
            if (!(appidStaticConfig.appid_thirdparty_dir = strdup(stoks[1])))
            {
                _dpd.errMsg("Failed to allocate a module directory");
                return;
            }
        }
        else
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Unknown AppId configuration option \"%s\"\n",
                                            *(_dpd.config_file), *(_dpd.config_line), toks[i]);
        }

        _dpd.tokenFree(&stoks, s_toks);
    }

    if (!appidStaticConfig.memcap)
        appidStaticConfig.memcap = APP_ID_MEMCAP_DEFAULT;
    if (!appidStaticConfig.app_stats_period)
        appidStaticConfig.app_stats_period = 5*60;
    if (!appidStaticConfig.app_stats_rollover_size)
        appidStaticConfig.app_stats_rollover_size = 20 * 1024 * 1024;
    if (!appidStaticConfig.app_stats_rollover_time)
        appidStaticConfig.app_stats_rollover_time = 24*60*60;

    if (!appidStaticConfig.app_id_detector_path[0])
        snprintf(appidStaticConfig.app_id_detector_path, sizeof(appidStaticConfig.app_id_detector_path), "%s", DEFAULT_APPID_DETECTOR_PATH);

    _dpd.tokenFree(&toks, num_toks);

    appIdConfigDump();
}

void appIdConfigDump(void)
{
    _dpd.logMsg("AppId Configuration\n");

    _dpd.logMsg("    Detector Path:          %s\n", appidStaticConfig.app_id_detector_path);
    _dpd.logMsg("    appStats Files:         %s\n", appidStaticConfig.app_stats_filename? appidStaticConfig.app_stats_filename:"NULL");
    _dpd.logMsg("    appStats Period:        %d secs\n", appidStaticConfig.app_stats_period);
    _dpd.logMsg("    appStats Rollover Size: %d bytes\n", appidStaticConfig.app_stats_rollover_size);
    _dpd.logMsg("    appStats Rollover time: %d secs\n", appidStaticConfig.app_stats_rollover_time);
    _dpd.logMsg("\n");
}

void AppIdAddGenericConfigItem(tAppIdConfig *pConfig, const char *name, void *pData)
{
    tAppidGenericConfigItem *pConfigItem;

    if (!(pConfigItem = malloc(sizeof(*pConfigItem))) ||
        !(pConfigItem->name = strdup(name)))
    {
        if (pConfigItem)
            free(pConfigItem);
        _dpd.errMsg("Failed to allocate a config item.");
        return;
    }
    pConfigItem->pData = pData;
    sflist_add_tail(&pConfig->genericConfigList, pConfigItem);
}

void *AppIdFindGenericConfigItem(const tAppIdConfig *pConfig, const char *name)
{
    tAppidGenericConfigItem *pConfigItem;

    // Search a module's configuration by its name
    for (pConfigItem = (tAppidGenericConfigItem *) sflist_first((SF_LIST*)&pConfig->genericConfigList);
         pConfigItem;
         pConfigItem = (tAppidGenericConfigItem *) sflist_next((SF_LIST*)&pConfig->genericConfigList))
    {
        if (strcmp(pConfigItem->name, name) == 0)
        {
            return pConfigItem->pData;
        }
    }

    return NULL;
}

void AppIdRemoveGenericConfigItem(tAppIdConfig *pConfig, const char *name)
{
    SF_LNODE                *pNode;

    // Search a module's configuration by its name
    for (pNode = sflist_first_node(&pConfig->genericConfigList);
         pNode;
         pNode = sflist_next_node(&pConfig->genericConfigList))
    {
        tAppidGenericConfigItem *pConfigItem = SFLIST_NODE_TO_DATA(pNode);
        if (strcmp(pConfigItem->name, name) == 0)
        {
            free(pConfigItem->name);
            free(pConfigItem);
            sflist_remove_node(&pConfig->genericConfigList, pNode);
            break;
        }
    }
}


