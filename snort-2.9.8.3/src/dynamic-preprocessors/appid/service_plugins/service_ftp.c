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


#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "appIdApi.h"
#include "appInfoTable.h"
#include "flow.h"
#include "service_api.h"
#include "service_util.h"

#define FTP_PORT    21
/*#define RNA_FTP_EXPECTED_ON_PORT    1 */

typedef enum
{
    FTP_STATE_CONNECTION,
    FTP_STATE_LOGIN,
    FTP_STATE_PASSWORD,
    FTP_STATE_ACCOUNT,
    FTP_STATE_CONNECTION_ERROR,
    FTP_STATE_MONITOR
} FTPState;

typedef enum
{
    FTP_REPLY_BEGIN,
    FTP_REPLY_MULTI,
    FTP_REPLY_MID
} FTPReplyState;

typedef enum
{
    FTP_CMD_NONE,
    FTP_CMD_PORT_EPRT,
    FTP_CMD_PASV_EPSV
} FTPCmd;

#define MAX_STRING_SIZE 64
typedef struct _SERVICE_FTP_DATA
{
    FTPState state;
    FTPReplyState rstate;
    int code;
    char vendor[MAX_STRING_SIZE];
    char version[MAX_STRING_SIZE];
    FTPCmd cmd;
    sfaddr_t address;
    uint16_t port;
} ServiceFTPData;

#pragma pack(1)

typedef struct _SERVICE_FTP_CODE
{
    uint8_t code[3];
    uint8_t sp;
} ServiceFTPCode;

#pragma pack()

static int ftp_init(const InitServiceAPI * const init_api);
MakeRNAServiceValidationPrototype(ftp_validate);

static tRNAServiceElement svc_element =
{
    .next = NULL,
    .validate = &ftp_validate,
    .detectorType = DETECTOR_TYPE_DECODER,
    .name = "ftp",
    .ref_count = 1,
    .current_ref_count = 1,
};

static RNAServiceValidationPort pp[] =
{
    {&ftp_validate, FTP_PORT, IPPROTO_TCP},
    {NULL, 0, 0}
};

tRNAServiceValidationModule ftp_service_mod =
{
    "FTP",
    &ftp_init,
    pp
};

#define FTP_PATTERN1 "220 "
#define FTP_PATTERN2 "220-"
#define FTP_PATTERN3 "FTP"
#define FTP_PATTERN4 "ftp"

static tAppRegistryEntry appIdRegistry[] =
{
    {APP_ID_FTP_CONTROL, APPINFO_FLAG_SERVICE_ADDITIONAL},
    {APP_ID_FTP_ACTIVE,  APPINFO_FLAG_SERVICE_ADDITIONAL},
    {APP_ID_FTP_PASSIVE, APPINFO_FLAG_SERVICE_ADDITIONAL},
    {APP_ID_FTPS,        APPINFO_FLAG_SERVICE_ADDITIONAL}
};

static int16_t ftp_data_app_id = 0;

static int ftp_init(const InitServiceAPI * const init_api)
{
    ftp_data_app_id = init_api->dpd->addProtocolReference("ftp-data");

    init_api->RegisterPattern(&ftp_validate, IPPROTO_TCP, (uint8_t *)FTP_PATTERN1, sizeof(FTP_PATTERN1)-1, 0, "ftp", init_api->pAppidConfig);
    init_api->RegisterPattern(&ftp_validate, IPPROTO_TCP, (uint8_t *)FTP_PATTERN2, sizeof(FTP_PATTERN2)-1, 0, "ftp", init_api->pAppidConfig);
    init_api->RegisterPattern(&ftp_validate, IPPROTO_TCP, (uint8_t *)FTP_PATTERN3, sizeof(FTP_PATTERN3)-1, -1, "ftp", init_api->pAppidConfig);
    init_api->RegisterPattern(&ftp_validate, IPPROTO_TCP, (uint8_t *)FTP_PATTERN4, sizeof(FTP_PATTERN4)-1, -1, "ftp", init_api->pAppidConfig);
	unsigned i;
	for (i=0; i < sizeof(appIdRegistry)/sizeof(*appIdRegistry); i++)
	{
		_dpd.debugMsg(DEBUG_LOG,"registering appId: %d\n",appIdRegistry[i].appId);
		init_api->RegisterAppId(&ftp_validate, appIdRegistry[i].appId, appIdRegistry[i].additionalInfo, init_api->pAppidConfig);
	}

    return 0;
}

static int ftp_validate_reply(const uint8_t *data, uint16_t *offset,
                              uint16_t size, ServiceFTPData *fd)
{
    const ServiceFTPCode *code_hdr;
    int tmp;
    FTPReplyState tmp_state;

    for (; *offset < size; (*offset)++)
    {
        /* Trim any blank lines (be a little tolerant) */
        for (; *offset<size; (*offset)++)
        {
            if (data[*offset] != 0x0D && data[*offset] != 0x0A) break;
        }

        switch (fd->rstate)
        {
        case FTP_REPLY_BEGIN:
            if (size - (*offset) < (int)sizeof(ServiceFTPCode)) return -1;

            code_hdr = (ServiceFTPCode *)(data + *offset);

            if (code_hdr->sp == '-') fd->rstate = FTP_REPLY_MULTI;
            else if (code_hdr->sp != ' ' && code_hdr->sp != 0x09) return -1;

            if (code_hdr->code[0] < '1' || code_hdr->code[0] > '5') return -1;
            fd->code = (code_hdr->code[0] - '0') * 100;

            if (code_hdr->code[1] < '0' || code_hdr->code[1] > '5') return -1;
            fd->code += (code_hdr->code[1] - '0') * 10;

            if (!isdigit(code_hdr->code[2])) return -1;
            fd->code += code_hdr->code[2] - '0';

            *offset += sizeof(ServiceFTPCode);
            tmp_state = fd->rstate;
            fd->rstate = FTP_REPLY_MID;
            for (; *offset < size; (*offset)++)
            {
                if (data[*offset] == 0x0D)
                {
                    (*offset)++;
                    if (*offset >= size) return -1;
                    if (data[*offset] == 0x0D)
                    {
                        (*offset)++;
                        if (*offset >= size) return -1;
                    }
                    if (data[*offset] != 0x0A) return -1;
                    fd->rstate = tmp_state;
                    break;
                }
                if (data[*offset] == 0x0A)
                {
                    fd->rstate = tmp_state;
                    break;
                }
                else if (!isprint(data[*offset]) && data[*offset] != 0x09) return -1;
            }
            if (fd->rstate == FTP_REPLY_MID) return -1;
            break;
        case FTP_REPLY_MULTI:
            if (size - *offset < (int)sizeof(ServiceFTPCode))
            {
                fd->rstate = FTP_REPLY_MID;
                for (; *offset < size; (*offset)++)
                {
                    if (data[*offset] == 0x0D)
                    {
                        (*offset)++;
                        if (*offset >= size) return -1;
                        if (data[*offset] == 0x0D)
                        {
                            (*offset)++;
                            if (*offset >= size) return -1;
                        }
                        if (data[*offset] != 0x0A) return -1;
                        fd->rstate = FTP_REPLY_MULTI;
                        break;
                    }
                    if (data[*offset] == 0x0A)
                    {
                        fd->rstate = FTP_REPLY_MULTI;
                        break;
                    }
                    if (!isprint(data[*offset]) && data[*offset] != 0x09) return -1;
                }
                if (fd->rstate == FTP_REPLY_MID) return -1;
            }
            else
            {
                code_hdr = (ServiceFTPCode *)(data + *offset);
                if (size - (*offset) >= (int)sizeof(ServiceFTPCode) &&
                    (code_hdr->sp == ' ' || code_hdr->sp == 0x09) &&
                    code_hdr->code[0] >= '1' && code_hdr->code[0] <= '5' &&
                    code_hdr->code[1] >= '1' && code_hdr->code[1] <= '5' &&
                    isdigit(code_hdr->code[2]))
                {
                    tmp = (code_hdr->code[0] - '0') * 100;
                    tmp += (code_hdr->code[1] - '0') * 10;
                    tmp += code_hdr->code[2] - '0';
                    if (tmp == fd->code)
                    {
                        *offset += sizeof(ServiceFTPCode);
                        fd->rstate = FTP_REPLY_BEGIN;
                    }
                }
                tmp_state = fd->rstate;
                fd->rstate = FTP_REPLY_MID;
                for (; *offset < size; (*offset)++)
                {
                    if (data[*offset] == 0x0D)
                    {
                        (*offset)++;
                        if (*offset >= size) return -1;
                        if (data[*offset] == 0x0D)
                        {
                            (*offset)++;
                            if (*offset >= size) return -1;
                        }
                        if (data[*offset] != 0x0A) return -1;
                        fd->rstate = tmp_state;
                        break;
                    }
                    if (data[*offset] == 0x0A)
                    {
                        fd->rstate = tmp_state;
                        break;
                    }
                    if (!isprint(data[*offset]) && data[*offset] != 0x09) return -1;
                }
                if (fd->rstate == FTP_REPLY_MID) return -1;
            }
            break;
        default:
            return -1;
        }
        if (fd->rstate == FTP_REPLY_BEGIN)
        {
            for (; *offset < size; (*offset)++)
            {
                if (data[*offset] == 0x0D)
                {
                    (*offset)++;
                    if (*offset >= size) return -1;
                    if (data[*offset] != 0x0A) return -1;
                }
                else if (!isspace(data[*offset])) break;
            }
            return fd->code;
        }
    }
    return 0;
}

static inline int _ftp_decode_number32(const uint8_t * *data, const uint8_t *end, uint8_t delimiter, uint32_t *number)
{
    const uint8_t *local_data;
    uint32_t local_number = 0;
    for (local_data = *data; local_data < end && *local_data == ' '; local_data++);
    if (local_data < end && *local_data == delimiter)
    {
        *number = 0;
        return -1;
    }
    while (local_data < end && *local_data != delimiter)
    {
        if (!isdigit(*local_data))
        {
            *number = 0;
            return -1;
        }
        local_number *= 10;
        local_number += *local_data - '0';
        local_data++;
    }
    if (local_data >= end || *local_data != delimiter)
    {
        *number = 0;
        return -1;
    }
    *number = local_number;
    *data = local_data+1;
    return 0;
}
static int ftp_decode_octet(const uint8_t * *data, const uint8_t *end, uint8_t delimiter, uint32_t *number)
{
    if (_ftp_decode_number32(data, end, delimiter, number) == -1) return -1;
    if (*number > 255)
    {
        *number = 0;
        return -1;
    }
    return 0;
}

static int ftp_decode_port_number(const uint8_t * *data, const uint8_t *end, uint8_t delimiter, uint32_t *number)
{
    if (_ftp_decode_number32(data, end, delimiter, number) == -1) return -1;
    if (*number > 65535)
    {
        *number = 0;
        return -1;
    }
    return 0;
}

static int ftp_validate_pasv(const uint8_t *data, uint16_t size,
                             uint32_t *address, uint16_t *port)
{
    const uint8_t *end;
    uint32_t tmp;

    *address = 0;
    *port = 0;

    end = data + size;
    data += sizeof(ServiceFTPCode);

    for (; data<end && *data!='('; data++);
    data++;
    if (data >= end) return 1;

    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    *address = tmp << 24;
    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    *address += tmp << 16;
    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    *address += tmp << 8;
    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    *address += tmp;
    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    *port = (uint16_t)(tmp << 8);
    if (ftp_decode_octet(&data, end, ')', &tmp)) return -1;
    *port += tmp;
    return 0;
}

static int ftp_validate_epsv(const uint8_t *data, uint16_t size,
                             uint16_t *port)
{
    const uint8_t *end;
    uint8_t delimiter;

    *port = 0;

    end = data + size;
    data += sizeof(ServiceFTPCode);

    for (; data<end && *data!='('; data++);
    data++;
    if (data >= end) return 1;

    delimiter = *data++;
    if (data >= end) return 1;

    for (; data<end && *data!=delimiter; data++);
    data++;
    if (data >= end) return 1;

    for (; data<end && *data!=delimiter; data++);
    data++;
    if (data >= end) return 1;

    while (data < end && *data != delimiter)
    {
        if (!isdigit(*data)) return -1;
        *port *= 10;
        *port += *data - '0';
        data++;
    }

    return 0;
}

static int ftp_validate_port(const uint8_t *data, uint16_t size,
                             sfaddr_t *address, uint16_t *port)
{
    const uint8_t *end;
    const uint8_t *p;
    uint32_t tmp;
    uint32_t addr;
    uint32_t addr2;

    memset(address,0,sizeof(sfaddr_t));
    *port = 0;

    end = data + size;

    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    addr = tmp << 24;
    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    addr += tmp << 16;
    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    addr += tmp << 8;
    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    addr += tmp;
    addr2 = htonl(addr); // make it network order before calling sfip_set_raw()
    sfip_set_raw(address, &addr2, AF_INET);

    if (ftp_decode_octet(&data, end, ',', &tmp)) return -1;
    *port = (uint16_t)(tmp << 8);
    p = end - 1;
    if (p > data)
    {
        if (*p == 0x0a)
        {
            p--;
            if (*p == 0x0d)
            {
                if (ftp_decode_octet(&data, end, 0x0d, &tmp)) return -1;
                *port += tmp;
                return 0;
            }
        }
    }
    if (ftp_decode_octet(&data, end, 0x0a, &tmp)) return -1;
    *port += tmp;
    return 0;
}
/* RFC 2428 support */
typedef struct addr_family_map_t
{
    uint16_t eprt_fam;
    uint16_t sfaddr_fam;
} addr_family_map;

static addr_family_map RFC2428_known_address_families[] =
{   { 1, AF_INET },
    { 2, AF_INET6 },
    { 0, 0 }
};

static int ftp_validate_eprt(const uint8_t *data, uint16_t size,
                             sfaddr_t *address, uint16_t *port)
{
    int index;
    int addrFamilySupported = 0;
    uint8_t delimiter;
    const uint8_t *end;
    uint32_t tmp;
    char tmp_str[INET6_ADDRSTRLEN+1];

    memset(address,0,sizeof(sfaddr_t));
    *port = 0;

    end = data + size;

    delimiter = *data++; // all delimiters will match this one.
    if (ftp_decode_octet(&data, end, delimiter, &tmp))
        return -1;

    // Look up the address family in the table.
    for (index = 0; !addrFamilySupported && RFC2428_known_address_families[index].eprt_fam != 0; index++)
    {
        if ( RFC2428_known_address_families[index].eprt_fam == (uint16_t)tmp )
        {
            addrFamilySupported = RFC2428_known_address_families[index].sfaddr_fam;
        }
    }
    if (!addrFamilySupported) // not an ipv4 or ipv6 address being provided.
        return -1;

    for (index = 0;
        index < INET6_ADDRSTRLEN && data < end && *data != delimiter;
        index++, data++ )
    {
        tmp_str[index] = *data;
    }
    tmp_str[index] = '\0'; // make the copied portion be nul terminated.

    if (sfip_convert_ip_text_to_binary( addrFamilySupported, tmp_str, &address->ip ) != SFIP_SUCCESS)
        return -1;

    address->family = addrFamilySupported;

    data++; // skip the delimiter at the end of the address substring.
    if (ftp_decode_port_number(&data, end, delimiter, &tmp)) // an error is returned if port was greater than 65535
        return -1;

    *port = (uint16_t)tmp;
    return 0;
}

static void CheckVendorVersion(const uint8_t *data, uint16_t init_offset,
                               uint16_t offset, ServiceFTPData *fd)
{
    static const unsigned char ven_hp[] = "Hewlett-Packard FTP Print Server";
    static const unsigned char ver_hp[] = "Version ";
    const unsigned char *p;
    const unsigned char *end;
    const unsigned char *ver;
    char *v;
    char *v_end;

    p = &data[init_offset];
    end = &data[offset-1];
    /* Search for the HP vendor string */
    if ((p=service_strstr(p, end-p, ven_hp, sizeof(ven_hp)-1)))
    {
        /* Found HP vendor string */
        strcpy(fd->vendor, (char *)ven_hp);
        /* Move just past the vendor string */
        p += sizeof(ven_hp) - 1;
        /* Search for the version string */
        if ((p = service_strstr(p, end-p, ver_hp, sizeof(ver_hp)-1)))
        {
            /* Found the version string.  Move just past the version string */
            ver = p + (sizeof(ver_hp) - 1);
            p = ver;
            v = fd->version;
            v_end = v + (MAX_STRING_SIZE - 1);
            while (p < end && *p && (isalnum(*p) || *p == '.'))
            {
                if (v < v_end)
                {
                    *v = *p;
                    v++;
                }
                p++;
            }
            *v = 0;
            /* Don't let the version end in . */
            if (v != fd->version && *(v-1) == '.')
            {
                v--;
                *v = 0;
            }
        }
    }
}

static inline void WatchForCommandResult(ServiceFTPData *fd, tAppIdData *flowp, FTPCmd command)
{
    if (fd->state != FTP_STATE_MONITOR)
    {
        setAppIdExtFlag(flowp, APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_CONTINUE);
        fd->state = FTP_STATE_MONITOR;
    }
    fd->cmd = command;
}

static inline void InitializeDataSession(tAppIdData *flowp,tAppIdData *fp)
{
    unsigned encryptedFlag = getAppIdExtFlag(flowp, APPID_SESSION_ENCRYPTED | APPID_SESSION_DECRYPTED);
    if (encryptedFlag == APPID_SESSION_ENCRYPTED)
    {
        fp->serviceAppId = APP_ID_FTPSDATA;
    }
    else
    {
        encryptedFlag = 0; // change (APPID_SESSION_ENCRYPTED | APPID_SESSION_DECRYPTED) case to zeroes.
        fp->serviceAppId = APP_ID_FTP_DATA;
    }
    setAppIdExtFlag(fp, APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_PORT_SERVICE_DONE | encryptedFlag);
    fp->rnaServiceState = RNA_STATE_FINISHED;
    fp->rnaClientState = RNA_STATE_FINISHED;
}

MakeRNAServiceValidationPrototype(ftp_validate)
{
    static const char FTP_PASV_CMD[] = "PASV";
    static const char FTP_EPSV_CMD[] = "EPSV";
    static const char FTP_PORT_CMD[] = "PORT ";
    static const char FTP_EPRT_CMD[] = "EPRT ";
    static const unsigned char ven_ms[] = "Microsoft FTP Service";
    static const unsigned char ver_ms[] = "(Version ";
    static const unsigned char ven_wu[] = "(Version wu-";
    static const unsigned char ven_proftpd[] = "ProFTPD";
    static const unsigned char ven_pureftpd[] = "Pure-FTPd";
    static const unsigned char ven_ncftpd[] = "NcFTPd";
    ServiceFTPData *fd;
    uint16_t offset;
    uint16_t init_offset;
    const unsigned char *p;
    const unsigned char *ven;
    const unsigned char *ver;
    int code;
    int code_index;
    uint32_t address;
    uint16_t port;
    tAppIdData *fp;
    int retval = SERVICE_INPROCESS;
    char *v;
    char *v_end;
    const unsigned char *begin;
    const unsigned char *end;

    if (!size)
        goto inprocess;

    //ignore packets while encryption is on in explicit mode. In future, this will be changed
    //to direct traffic to SSL detector to extract payload from certs. This will require manintaining
    //two detector states at the same time.
    if (getAppIdExtFlag(flowp, APPID_SESSION_ENCRYPTED))
    {
        if (!getAppIdExtFlag(flowp, APPID_SESSION_DECRYPTED))
        {
            goto inprocess;
        }
    }

    fd = ftp_service_mod.api->data_get(flowp, ftp_service_mod.flow_data_index);
    if (!fd)
    {
        fd = calloc(1, sizeof(*fd));
        if (!fd)
            return SERVICE_ENOMEM;
        if (ftp_service_mod.api->data_add(flowp, fd, ftp_service_mod.flow_data_index, &free))
        {
            free(fd);
            return SERVICE_ENOMEM;
        }
        fd->state = FTP_STATE_CONNECTION;
        fd->rstate = FTP_REPLY_BEGIN;
        fd->cmd = FTP_CMD_NONE;
    }

    if (dir != APP_ID_FROM_RESPONDER)
    {
        if (data[size-1] != 0x0a) goto inprocess;

        if (size > sizeof(FTP_PORT_CMD)-1 &&
            strncasecmp((char *)data, FTP_PORT_CMD, sizeof(FTP_PORT_CMD)-1) == 0)
        {
            if (ftp_validate_port(data+(sizeof(FTP_PORT_CMD)-1),
                                  size-(sizeof(FTP_PORT_CMD)-1),
                                  &fd->address, &fd->port) == 0)
            {
                WatchForCommandResult(fd, flowp, FTP_CMD_PORT_EPRT);
            }
        }
        else if (size > sizeof(FTP_EPRT_CMD)-1 &&
            strncasecmp((char *)data, FTP_EPRT_CMD, sizeof(FTP_EPRT_CMD)-1) == 0)
        {
            if (ftp_validate_eprt(data+(sizeof(FTP_EPRT_CMD)-1),
                                  size-(sizeof(FTP_EPRT_CMD)-1),
                                  &fd->address, &fd->port) == 0)
            {
                WatchForCommandResult(fd, flowp, FTP_CMD_PORT_EPRT);
            }
        }
        else if ( size > sizeof(FTP_PASV_CMD)-1 &&
                  ( strncasecmp((char *)data, FTP_PASV_CMD, sizeof(FTP_PASV_CMD)-1) == 0 ||
                    strncasecmp((char *)data, FTP_EPSV_CMD, sizeof(FTP_EPSV_CMD)-1) == 0 )
                )
        {
            WatchForCommandResult(fd, flowp, FTP_CMD_PASV_EPSV);
        }
        goto inprocess;
    }

    v_end = fd->version;
    v_end += MAX_STRING_SIZE - 1;

    offset = 0;
    while (offset < size)
    {
        init_offset = offset;
        if ((code=ftp_validate_reply(data, &offset, size, fd)) < 0) goto fail;
        if (!code) goto inprocess;

        switch (fd->state)
        {
        case FTP_STATE_CONNECTION:
            switch (code)
            {
            case 120: /*system will be ready in nn minutes */
                break;
            case 220: /*service ready for new user */
                fd->state = FTP_STATE_LOGIN;
                begin = &data[init_offset];
                end = &data[offset-1];
                if (service_strstr(begin, end-begin, ven_ms, sizeof(ven_ms)-1))
                {
                    strcpy(fd->vendor, (char *)ven_ms);
                    if ((p = service_strstr(begin, end-begin, ver_ms, sizeof(ver_ms)-1)))
                    {
                        ver = p + (sizeof(ver_ms) - 1);
                        v = fd->version;
                        for (p=ver; p<end && *p && *p != ')'; p++)
                        {
                            if (v < v_end)
                            {
                                *v = *p;
                                v++;
                            }
                        }
                        *v = 0;
                        if (p >= end || !(*p))
                        {
                            /* did not find a closing ), no version */
                            fd->version[0] = 0;
                        }
                    }
                }
                else if ((p=service_strstr(begin, end-begin, ven_wu, sizeof(ven_wu)-1)))
                {
                    strcpy(fd->vendor, "wu");
                    ver = p + (sizeof(ven_wu) - 1);
                    v = fd->version;
                    for (p=ver; p<end && *p && *p != ' '; p++)
                    {
                        if (v < v_end)
                        {
                            *v = *p;
                            v++;
                        }
                    }
                    *v = 0;
                    if (p >= end || !(*p))
                    {
                        /* did not find a space, no version */
                        fd->version[0] = 0;
                    }
                }
                else if ((p=service_strstr(begin, end-begin, ven_proftpd, sizeof(ven_proftpd)-1)))
                {
                    strcpy(fd->vendor, (char *)ven_proftpd);
                    ver = p + (sizeof(ven_proftpd) - 1);
                    if (*ver == ' ')
                    {
                        ver++;
                        v = fd->version;
                        for (p=ver; p<end && *p && *p != ' '; p++)
                        {
                            if (v < v_end)
                            {
                                *v = *p;
                                v++;
                            }
                        }
                        *v = 0;
                        if (p >= end || !(*p))
                        {
                            /* did not find a space, no version */
                            fd->version[0] = 0;
                        }
                    }
                }
                else if (service_strstr(begin, end-begin, ven_pureftpd, sizeof(ven_pureftpd)-1))
                {
                    strcpy(fd->vendor, (char *)ven_pureftpd);
                }
                else if (service_strstr(begin, end-begin, ven_ncftpd, sizeof(ven_ncftpd)-1))
                {
                    strcpy(fd->vendor, (char *)ven_ncftpd);
                }
                else
                {
                    /* Look for (Vendor Version:  or  (Vendor Version) */
                    for (p=begin; p<end && *p && *p!='('; p++);
                    if (p < end)
                    {
                        p++;
                        ven = p;
                        for (; p<end && *p && *p!=' '; p++);
                        if (p < end && *p)
                        {
                            const unsigned char *ven_end;
                            const char *vendor_end;

                            ven_end = p;
                            ver = p + 1;
                            v = fd->vendor;
                            vendor_end = v + (MAX_STRING_SIZE - 1);
                            for (p=ven; p<ven_end; p++)
                            {
                                if (!isprint(*p)) break;
                                if (v < vendor_end)
                                {
                                    *v = *p;
                                    v++;
                                }
                            }
                            if (p >= ven_end)
                            {
                                *v = 0;
                                for (p=ver; p<end && *p && *p!=':'; p++);
                                if (p>=end || !(*p))
                                {
                                    for (p=ver; p<end && *p && *p!=')'; p++);
                                }
                                if (p < end && *p)
                                {
                                    const unsigned char *ver_end;
                                    ver_end = p;
                                    v = fd->version;
                                    for (p=ver; p<ver_end; p++)
                                    {
                                        if (!isprint(*p)) break;
                                        if (v < v_end)
                                        {
                                            *v = *p;
                                            v++;
                                        }
                                    }
                                    if (p >= ver_end)
                                    {
                                        *v = 0;
                                    }
                                    else
                                    {
                                        /* Non-printable characters.  No vendor or version */
                                        fd->vendor[0] = 0;
                                        fd->version[0] = 0;
                                    }
                                }
                                else
                                {
                                    /* No : or ).  No vendor */
                                    fd->vendor[0] = 0;
                                }
                            }
                            else
                            {
                                /* Non-printable characters.  No vendor */
                                fd->vendor[0] = 0;
                            }
                        }
                    }
                }
                break;
            case 110: /* restart mark reply */
            case 125: /* connection is open start transferring file */
            case 150: /* Opening command */
            case 200: /*command ok */
            case 202: /*command not implemented */
            case 211: /* system status */
            case 212: /* directory status */
            case 213: /* file status */
            case 214: /* help message */
            case 215: /* name system type */
            case 225: /* data connection open */
            case 226: /* Transfer complete */
            case 227: /*entering passive mode */
            case 230: /*user loggined */
            case 250: /* CWD command successful */
            case 257: /* PATHNAME created */
            case 331: /* login ok need password */
            case 332: /*new account for login */
            case 350: /*requested file action pending futher information */
            case 450: /*requested file action not taken */
            case 451: /*requested file action aborted */
            case 452: /*requested file action not taken not enough space */
            case 500: /*syntax error */
            case 501: /*not recognozed */
            case 502: /*not recognozed */
            case 503: /*bad sequence of commands */
            case 504: /*command not implemented */
            case 530: /*login incorrect */
            case 532: /*new account for storing file */
            case 550: /*requested action not taken */
            case 551: /*requested action aborted :page type unknown */
            case 552: /*requested action aborted */
            case 553: /*requested action not taken file name is not allowed */
                setAppIdExtFlag(flowp, APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_CONTINUE);
                fd->state = FTP_STATE_MONITOR;
                break;
            case 221: /*good bye */
            case 421: /*service not available closing connection */
                fd->state = FTP_STATE_CONNECTION_ERROR;
                break;
            default:
                goto fail;
            }
            break;
        case FTP_STATE_LOGIN:
            code_index = code / 100;
            switch (code_index)
            {
            case 2:
                switch (code)
                {
                case 221:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                case 230:
                    if (!fd->vendor[0] && !fd->version[0])
                        CheckVendorVersion(data, init_offset, offset, fd);
                    setAppIdExtFlag(flowp, APPID_SESSION_CONTINUE);
                    fd->state = FTP_STATE_MONITOR;
                    retval = SERVICE_SUCCESS;
                    break;
                case 234:
                    {
                        setAppIdExtFlag(flowp, APPID_SESSION_CONTINUE);
                        retval = SERVICE_SUCCESS;
                        /*
                        // we do not set the state to FTP_STATE_MONITOR here because we don't know
                        // if there will be SSL decryption to allow us to see what we are interested in.
                        // Let the WatchForCommandResult() usage elsewhere take care of it.
                        */
                        setAppIdExtFlag(flowp, APPID_SESSION_ENCRYPTED);
                        setAppIdIntFlag(flowp, APPID_SESSION_STICKY_SERVICE);
                    }
                    break;
                default:
                    break;
                }
                break;
            case 3:
                switch (code)
                {
                case 331:
                    fd->state = FTP_STATE_PASSWORD;
                    break;
                case 332:
                    fd->state = FTP_STATE_ACCOUNT;
                    break;
                default:
                    break;
                }
                break;
            case 4:
                switch (code)
                {
                case 421:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                case 431:
                    break;
                default:
                    goto fail;
                }
                break;
            case 5:
                break;
            default:
                goto fail;
            }
            break;
        case FTP_STATE_PASSWORD:
            code_index = code / 100;
            switch (code_index)
            {
            case 2:
                switch (code)
                {
                case 221:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                case 202:
                case 230:
                    if (!fd->vendor[0] && !fd->version[0])
                        CheckVendorVersion(data, init_offset, offset, fd);
                    setAppIdExtFlag(flowp, APPID_SESSION_CONTINUE);
                    fd->state = FTP_STATE_MONITOR;
                    retval = SERVICE_SUCCESS;
                default:
                    break;
                }
                break;
            case 3:
                switch (code)
                {
                case 332:
                    fd->state = FTP_STATE_ACCOUNT;
                    break;
                default:
                    break;
                }
                break;
            case 4:
                switch (code)
                {
                case 421:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                default:
                    goto fail;
                }
                break;
            case 5:
                switch (code)
                {
                case 500:
                case 501:
                case 503:
                case 530:
                    fd->state = FTP_STATE_LOGIN;
                    break;
                default:
                    goto fail;
                }
                break;
            default:
                goto fail;
            }
            break;
        case FTP_STATE_ACCOUNT:
            code_index = code / 100;
            switch (code_index)
            {
            case 2:
                switch (code)
                {
                case 202:
                case 230:
                    if (!fd->vendor[0] && !fd->version[0])
                        CheckVendorVersion(data, init_offset, offset, fd);
                    setAppIdExtFlag(flowp, APPID_SESSION_CONTINUE);
                    fd->state = FTP_STATE_MONITOR;
                    retval = SERVICE_SUCCESS;
                default:
                    break;
                }
                break;
            case 3:
                switch (code)
                {
                case 332:
                    fd->state = FTP_STATE_ACCOUNT;
                    break;
                default:
                    break;
                }
                break;
            case 4:
                switch (code)
                {
                case 421:
                    fd->state = FTP_STATE_CONNECTION_ERROR;
                    break;
                default:
                    goto fail;
                }
                break;
            case 5:
                switch (code)
                {
                case 500:
                case 501:
                case 503:
                case 530:
                    fd->state = FTP_STATE_LOGIN;
                    break;
                default:
                    goto fail;
                }
                break;
            default:
                goto fail;
            }
            break;
        case FTP_STATE_MONITOR: // looking for the DATA channel info in the result
            switch (code)
            {
            case 227:
                {
                    code = ftp_validate_pasv(data + init_offset,
                                             (uint16_t)(offset-init_offset),
                                             &address, &port);
                    if (!code)
                    {
                        sfaddr_t ip;
                        sfaddr_t *sip;
                        sfaddr_t *dip;
                        uint32_t addr;

                        dip = GET_DST_IP(pkt);
                        sip = GET_SRC_IP(pkt);
                        addr = htonl(address);
                        sfip_set_raw(&ip, &addr, AF_INET);
                        fp = ftp_service_mod.api->flow_new(flowp, pkt, dip, 0, &ip, port, flowp->proto, ftp_data_app_id,
                                                           APPID_EARLY_SESSION_FLAG_FW_RULE);
                        if (fp)
                        {
                            InitializeDataSession(flowp,fp);
                        }
                        if (!sfip_fast_eq6(&ip, sip))
                        {
                            fp = ftp_service_mod.api->flow_new(flowp, pkt, dip, 0, sip, port, flowp->proto, ftp_data_app_id,
                                                               APPID_EARLY_SESSION_FLAG_FW_RULE);
                            if (fp)
                            {
                                InitializeDataSession(flowp,fp);
                            }
                        }
                        ftp_service_mod.api->add_payload(flowp, APP_ID_FTP_PASSIVE); // Passive mode FTP is reported as a payload id
                    }
                    else if (code < 0)
                    {
                        goto fail;
                    }
                }
                break;
            case 229:
                {
                    code = ftp_validate_epsv(data + init_offset,
                                             (uint16_t)(offset-init_offset),
                                             &port);

                    if (!code)
                    {
                        sfaddr_t *sip;
                        sfaddr_t *dip;

                        dip = GET_DST_IP(pkt);
                        sip = GET_SRC_IP(pkt);
                        fp = ftp_service_mod.api->flow_new(flowp, pkt, dip, 0, sip, port, flowp->proto, ftp_data_app_id,
                                                           APPID_EARLY_SESSION_FLAG_FW_RULE);
                        if (fp)
                        {
                            InitializeDataSession(flowp,fp);
                        }
                        ftp_service_mod.api->add_payload(flowp, APP_ID_FTP_PASSIVE); // Passive mode FTP is reported as a payload id
                    }
                    else if (code < 0)
                    {
                        goto fail;
                    }
                }
                break;
            case 200:
                if (fd->cmd == FTP_CMD_PORT_EPRT)
                {
                    sfaddr_t *sip;

                    sip = GET_SRC_IP(pkt);
                    fp = ftp_service_mod.api->flow_new(flowp, pkt, sip, 0, &fd->address, fd->port, flowp->proto, ftp_data_app_id,
                                                       APPID_EARLY_SESSION_FLAG_FW_RULE);
                    if (fp)
                    {
                        InitializeDataSession(flowp,fp);
                    }
                    ftp_service_mod.api->add_payload(flowp, APP_ID_FTP_ACTIVE); // Active mode FTP is reported as a payload id
                }
                break;
            default:
                break;
            }
            fd->cmd = FTP_CMD_NONE;
            break;
        case FTP_STATE_CONNECTION_ERROR:
        default:
            goto fail;
        }
    }

    switch (retval)
    {
    default:
    case SERVICE_INPROCESS:
inprocess:
        if (!getAppIdExtFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
        {
            ftp_service_mod.api->service_inprocess(flowp, pkt, dir, &svc_element);
        }
        return SERVICE_INPROCESS;

    case SERVICE_SUCCESS:
        if (!getAppIdExtFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
        {
            unsigned encryptedFlag = getAppIdExtFlag(flowp, APPID_SESSION_ENCRYPTED | APPID_SESSION_DECRYPTED);
            ftp_service_mod.api->add_service(flowp, pkt, dir, &svc_element,
                                             encryptedFlag == APPID_SESSION_ENCRYPTED ? // FTPS only when encrypted==1 decrypted==0
                                                APP_ID_FTPS : APP_ID_FTP_CONTROL,
                                             fd->vendor[0] ? fd->vendor:NULL,
                                             fd->version[0] ? fd->version:NULL, NULL);
        }
        return SERVICE_SUCCESS;

    case SERVICE_NOMATCH:
fail:
        if (!getAppIdExtFlag(flowp, APPID_SESSION_SERVICE_DETECTED))
        {
            ftp_service_mod.api->fail_service(flowp, pkt, dir, &svc_element, ftp_service_mod.flow_data_index, pConfig);
        }
        clearAppIdExtFlag(flowp, APPID_SESSION_CONTINUE);
        return SERVICE_NOMATCH;
    }
}

