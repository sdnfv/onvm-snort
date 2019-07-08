/*
** (c) Copyright [2016] Hewlett Packard Enterprise Development LP
** Author: Jean Tourrilhes <jt@labs.hpe.com>
** Based on various other DAQs, such as DAQ-DPKD, and other NetVM NFs
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
** along with this program; if not, write to the Free Software Foundation, Inc.,
** 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//----- DAQ headers ----
#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>

//----- DPDK headers ----
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_cycles.h>

//----- NetVM header files and tags ----
#include <onvm_common.h>
#include <onvm_sc_common.h>
#include <onvm_pkt_helper.h>
#include <onvm_nflib.h>

#define NF_TAG "snort"
#define _NF_MEMPOOL_NAME "NF_INFO_MEMPOOL"

#define DAQ_NETVM_VERSION 1

#define MAX_ARGS 64
#define PKT_READ_SIZE  ((uint16_t)32) 

/* Context for the DAQ.
 * We need only a single context, because we have only a single connection
 * to NetVM which get packets from all interfaces. */
typedef struct _netvm_context
{
    volatile int break_loop;
    char *filter;
    int timeout;
    DAQ_State state;
    int snaplen;
    int promisc_flag;
    DAQ_Stats_t stats;
    struct sfbpf_program fcode;
    struct onvm_nf_info* info;
    struct rte_ring *tx_ring;
    struct rte_ring *rx_ring;
    volatile struct client_tx_stats *tx_stats;
    char errbuf[256];
} NetVM_Context_t;

/* struct for the netvm */
struct onvm_nf_info *nf_info;
struct rte_mbuf* pkt1;
//static int once = 1;

/* Service ID of next NF */
static uint32_t destination;

static void netvm_daq_reset_stats(void *handle);


/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> \n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0;

        while ((c = getopt(argc, argv, "d:")) != -1) {
                switch (c) {
                case 'd':
                        destination = strtoul(optarg, NULL, 10);
                        dst_flag = 1;
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'd')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (optopt == 'p')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                        else
                                RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        usage(progname);
                        return -1;
                }
        }

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Simple Forward NF requires destination flag -d.\n");
                return -1;
        }

        return optind;
}

/* Convert DAQ arg string into an argv[] array */
static int parse_args(char *inputstring, char **argv)
{
    char **ap;

    for (ap = argv; (*ap = strsep(&inputstring, " \t")) != NULL;)
    {
        if (**ap != '\0')
            if (++ap >= &argv[MAX_ARGS])
                break;
    }
    return ap - argv;
}

/* Initialise the DAQ module and the DAQ context. */
static int netvm_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    NetVM_Context_t *netvmc = NULL;
    DAQ_Dict *entry;
    int ret, rval = DAQ_ERROR;
    char *netvm_args = NULL;
    char argv0[] = "fake";
    char *argv[MAX_ARGS + 1];
    int argc;

    //printf("->netvm_daq_initialize()\n");

    /* Sanity check ! */
    if (rte_mempool_ops_table.num_ops == 0) {
        snprintf(errbuf, errlen, "%s: DPDK constructors not linked in, please link whole DPDK archive!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    /* Import the DPDK/Netvm arguments */
    for (entry = config->values; entry; entry = entry->next) {
        if (!strcmp(entry->key, "netvm_args"))
            netvm_args = entry->value;
    }
    if (!netvm_args) {
        snprintf(errbuf, errlen, "%s: Missing EAL arguments!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    //printf("netvm_args %s \n", netvm_args);
    argv[0] = argv0;
    argc = parse_args(netvm_args, &argv[1]) + 1;
    optind = 1;

    /* Initialise NetVM, which initialise DPDK using rte_eal_init() */
    printf("netvm going to init\n");
    ret = onvm_nflib_init(argc, argv, NF_TAG);
    if (ret < 0)
    {
        snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        return rval;
    }
    /* At this point, we are *not* running. */
    //nf_info->status = NF_STOPPED;
    printf("netvm init done\n");
    /* Complete onvm handshake */
    onvm_nflib_nf_ready(nf_info);

    /* Parse app args */
    if (parse_app_args(argc - ret, argv + ret, "daq_netvm") < 0) {
        snprintf(errbuf, errlen, "%s: Can't parse DAQ_NetVM arguments!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto shutdown;
    }

    /* Allocate a DAQ context for ourselves. */
    netvmc = calloc(1, sizeof(NetVM_Context_t));
    if (!netvmc) {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for NetVM context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto shutdown;
    }
    netvmc->info = nf_info;
    netvmc->snaplen = config->snaplen;
    netvmc->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
    netvmc->promisc_flag = (config->flags & DAQ_CFG_PROMISC);
    netvmc->tx_ring = onvm_nflib_get_tx_ring(nf_info);
    netvmc->rx_ring = onvm_nflib_get_rx_ring(nf_info);
    netvmc->tx_stats = onvm_nflib_get_tx_stats(nf_info);
    //printf("netvm timeout = %d\n", netvmc->timeout);

    netvmc->state = DAQ_STATE_INITIALIZED;
    *ctxt_ptr = netvmc;
    //printf("<-netvm_daq_initialize()\n");

    return DAQ_SUCCESS;

shutdown:
    onvm_nflib_stop();
err:
    if (netvmc) {
        free(netvmc);
    }
    return rval;
}
  
static int netvm_daq_set_filter(void *handle, const char *filter)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;
    struct sfbpf_program fcode;

    if (netvmc->filter)
        free(netvmc->filter);

    netvmc->filter = strdup(filter);
    if (!netvmc->filter)
    {
      DPE(netvmc->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(netvmc->snaplen, DLT_EN10MB, &fcode, netvmc->filter, 1, 0) < 0)
    {
        DPE(netvmc->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&netvmc->fcode);

    netvmc->fcode.bf_len = fcode.bf_len;
    netvmc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int netvm_daq_start(void *handle)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;

    //printf("->netvm_daq_start()\n");
    netvm_daq_reset_stats(handle);

    //nf_info->status = NF_RUNNING;
    netvmc->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

static int netvm_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;
    struct onvm_nf_info* info = netvmc->info;
    int max_pkts = RTE_MIN(cnt > 0 ? cnt : PKT_READ_SIZE, PKT_READ_SIZE);
    void *pktsRX[PKT_READ_SIZE];
    void *pktsTX[PKT_READ_SIZE];
    struct timeval ts;
    int c = 0;
    uint16_t nb_pkts;
    uint16_t i, j;
    int tx_batch_size;
    uint64_t start;
    double cpu_time;
    double pps;

    //printf("->netvm_daq_acquire(%d - %d)\n", cnt, max_pkts);
    //if (once) {
    //  printf("netvm_daq_acquire() - rx_ring = %p\n", netvmc->rx_ring);
    //  once = 0;
    //}

    /* Usually, cnt is zero, which mean max packet burst */
    while (c < cnt || cnt <= 0) {

	//printf("netvm_daq_acquire: try nb_pkt = %d\n", nb_pkts);

	/* Check if netvm_daq_breakloop() was called */
	if (netvmc->break_loop) {
            netvmc->break_loop = 0;
            return 0;
        }
	    
	start = rte_get_tsc_cycles();
	
	/* Dequeue all packets in ring up to max possible. */
	nb_pkts = rte_ring_dequeue_burst(netvmc->rx_ring, pktsRX, max_pkts);

	//printf("netvm_daq_acquire: got nb_pkt = %d\n", nb_pkts);
	if(unlikely(nb_pkts == 0)) {
            struct timeval now;

            if (netvmc->timeout == -1)
                continue;

            /* If time out, return control to the caller. */
            gettimeofday(&now, NULL);
            if (now.tv_sec > ts.tv_sec ||
		(now.tv_usec - ts.tv_usec) > netvmc->timeout * 1000) {
	        //printf("<-netvm_daq_acquire() - timeout\n");
                return 0;
	    } else
	        continue;
	    /* Never reached */
	}
	gettimeofday(&ts, NULL);
	//printf("netvm_daq_acquire: got nb_pkt = %d\n", nb_pkts);

	/* Process each packet in the burst. */
        tx_batch_size = 0;
	for (i = 0; i < nb_pkts; i++) {
	    struct rte_mbuf* pkt;
	    struct onvm_pkt_meta* meta;
	    const uint8_t *data;
	    uint16_t len;
	    DAQ_PktHdr_t daqhdr;
	    DAQ_Verdict verdict = DAQ_VERDICT_PASS;

	    pkt = (struct rte_mbuf*)pktsRX[i];
	    meta = onvm_get_pkt_meta(pkt);
	    data = rte_pktmbuf_mtod(pkt, void *);
	    len = rte_pktmbuf_data_len(pkt);
            netvmc->stats.hw_packets_received++;

	    /* Filter packets */
	    if (netvmc->fcode.bf_insns
		&& sfbpf_filter(netvmc->fcode.bf_insns, data, len, len) == 0) {
	        netvmc->stats.packets_filtered++;
	    } else {
	        daqhdr.ts = ts;
		daqhdr.caplen = len;
		daqhdr.pktlen = len;
		daqhdr.ingress_index = pkt->port;
		/* Egress depend on subsequent NF, so impossible to know */
		daqhdr.egress_index = DAQ_PKTHDR_UNKNOWN;
		daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
		daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
		daqhdr.flags = 0;
		daqhdr.opaque = 0;
		daqhdr.priv_ptr = NULL;
		daqhdr.address_space_id = 0;

		/* Give packet to Snort */
		if (callback) {
		    verdict = callback(user, &daqhdr, data);
		    if (verdict >= MAX_DAQ_VERDICT)
		        verdict = DAQ_VERDICT_PASS;
		    netvmc->stats.verdicts[verdict]++;
		    /* Reduce everything to pass or block/drop */
		    verdict = verdict_translation_table[verdict];
		}
		netvmc->stats.packets_received++;
		c++;
	    }

	    if (verdict == DAQ_VERDICT_PASS) {
	        /* Direct packet to next NF */
	        meta->action = ONVM_NF_ACTION_TONF;
		meta->destination = destination;
	    } else {
	        /* Ask NetVM to drop the packet */
	        meta->action = ONVM_NF_ACTION_DROP;
	    }

	    /* Enqueue on return to NetVM */
	    pktsTX[tx_batch_size++] = pktsRX[i];
	}
	 
	cpu_time = (double)(rte_get_tsc_cycles() - start) / rte_get_tsc_hz();
	pps = (double) (nb_pkts / cpu_time);
	
	printf("CPU Time: %f\n", cpu_time);
	printf("PPS: %f\n", pps);

	/* Give returned burst of packets back to NetVM manager. */
	if (unlikely(tx_batch_size > 0 && rte_ring_enqueue_bulk(netvmc->tx_ring, pktsTX, tx_batch_size) == -ENOBUFS)) {
	    netvmc->tx_stats->tx_drop[info->instance_id] += tx_batch_size;
	    for (j = 0; j < tx_batch_size; j++) {
	        rte_pktmbuf_free(pktsTX[j]);
	    }
	} else {
	    netvmc->tx_stats->tx[info->instance_id] += tx_batch_size;
	}
    }
    //printf("<-netvm_daq_acquire() - count\n");
    return 0;
}

static int netvm_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;
    printf("->netvm_daq_inject()\n");

    // Todo...

    return DAQ_SUCCESS;
}

static int netvm_daq_breakloop(void *handle)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;

    netvmc->break_loop = 1;

    return DAQ_SUCCESS;

}

static int netvm_daq_stop(void *handle)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;
    //printf("->netvm_daq_stop()\n");

    nf_info->status = NF_STOPPED;
    netvmc->state = DAQ_STATE_STOPPED;

    return DAQ_SUCCESS;
}

static void netvm_daq_shutdown(void *handle)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;
    //printf("->netvm_daq_shutdown()\n");

    onvm_nflib_stop();

    if (netvmc->filter)
        free(netvmc->filter);
    free(netvmc);
}

static DAQ_State netvm_daq_check_status(void *handle)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;

    return netvmc->state;
}

static int netvm_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;

    rte_memcpy(stats, &netvmc->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void netvm_daq_reset_stats(void *handle)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;

    memset(&netvmc->stats, 0, sizeof(DAQ_Stats_t));
}

static int netvm_daq_get_snaplen(void *handle)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;

    return netvmc->snaplen;
}

static uint32_t netvm_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
        DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF |
        DAQ_CAPA_DEVICE_INDEX;
}

static int netvm_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *netvm_daq_get_errbuf(void *handle)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;

    return netvmc->errbuf;
}

static void netvm_daq_set_errbuf(void *handle, const char *string)
{
    NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;

    if (!string)
        return;

    DPE(netvmc->errbuf, "%s", string);
}

static int netvm_daq_get_device_index(void *handle, const char *device)
{
    //NetVM_Context_t *netvmc = (NetVM_Context_t *) handle;
    int port;

    if (strncmp(device, "dpdk", 4) != 0 || sscanf(&device[4], "%d", &port) != 1)
        return DAQ_ERROR_NODEV;

    return port;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t netvm_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_API_VERSION,
    /* .module_version = */ DAQ_NETVM_VERSION,
    /* .name = */ "netvm",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .initialize = */ netvm_daq_initialize,
    /* .set_filter = */ netvm_daq_set_filter,
    /* .start = */ netvm_daq_start,
    /* .acquire = */ netvm_daq_acquire,
    /* .inject = */ netvm_daq_inject,
    /* .breakloop = */ netvm_daq_breakloop,
    /* .stop = */ netvm_daq_stop,
    /* .shutdown = */ netvm_daq_shutdown,
    /* .check_status = */ netvm_daq_check_status,
    /* .get_stats = */ netvm_daq_get_stats,
    /* .reset_stats = */ netvm_daq_reset_stats,
    /* .get_snaplen = */ netvm_daq_get_snaplen,
    /* .get_capabilities = */ netvm_daq_get_capabilities,
    /* .get_datalink_type = */ netvm_daq_get_datalink_type,
    /* .get_errbuf = */ netvm_daq_get_errbuf,
    /* .set_errbuf = */ netvm_daq_set_errbuf,
    /* .get_device_index = */ netvm_daq_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL
};
