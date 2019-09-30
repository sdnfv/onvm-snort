#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([daq], [2.0.6], [snort-team@sourcefire.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([sfbpf/gencode.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Enable visibility if we can
AC_ENABLE_VISIBILITY()
# Special compiler flags for ICC, etc.
AC_SF_COMPILER_SETUP()

# IPv6 configuration
AC_ARG_ENABLE(ipv6, 
AC_HELP_STRING([--enable-ipv6],[build IPv6-capable version @<:@default=yes, if getaddrinfo available@:>@]),
    [],
    [enable_ipv6=ifavailable])
if test "$enable_ipv6" != "no"; then
    AC_CHECK_FUNC(getaddrinfo,
        [
        AC_DEFINE(INET6,1,[System IPv6 support])
        ],
        [
        if test "$enable_ipv6" != "ifavailable"; then
            AC_MSG_FAILURE([--enable-ipv6 was given, but getaddrinfo isn't available])
        fi
        ])
fi

# YACC/LEX configuration
AC_LBL_LEX_AND_YACC(V_LEX, V_YACC, sfbpf_)
if test "$V_LEX" = lex ; then
# Some versions of lex can't handle the definitions section of scanner.l .
# Try lexing it and complain if it can't deal.
    AC_CACHE_CHECK([for capable lex], sf_cv_capable_lex,
        if lex -t scanner.l > /dev/null 2>&1; then
            sf_cv_capable_lex=yes
        else
            sf_cv_capable_lex=insufficient
        fi)
    if test $sf_cv_capable_lex = insufficient ; then
        AC_MSG_ERROR(
        [Your operating system's lex is insufficient to compile
         libsfbpf. You should install both bison and flex.
         flex is a lex replacement that has many advantages,
         including being able to compile libsfbpf.  For more
         information, see http://www.gnu.org/software/flex/flex.html .])
    fi
fi

save_LIBS=${LIBS}

# Checks for libraries.
AC_ARG_WITH(libpcap_includes,
            [  --with-libpcap-includes=DIR    libpcap include directory],
            [with_pcap_includes="$withval"], [with_pcap_includes="no"])

AC_ARG_WITH(libpcap_libraries,
            [  --with-libpcap-libraries=DIR   libpcap library directory],
            [with_pcap_libraries="$withval"], [with_pcap_libraries="no"])

if test "x$with_pcap_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_pcap_includes}"
fi

if test "x$with_pcap_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS} -L${with_pcap_libraries}"
fi

AC_ARG_WITH(dnet_includes,
            [  --with-dnet-includes=DIR    dnet include directory],
            [with_dnet_includes="$withval"], [with_dnet_includes="no"])

AC_ARG_WITH(dnet_libraries,
            [  --with-dnet-libraries=DIR   dnet library directory],
            [with_dnet_libraries="$withval"], [with_dnet_libraries="no"])

if test "x$with_dnet_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_dnet_includes}"
else
    CPPFLAGS="${CPPFLAGS} `dnet-config --cflags 2>/dev/null`"
fi

if test "x$with_dnet_libraries" != "xno"; then
    DNET_LDPATH="-L${with_dnet_libraries}"
else
    DNET_LDFLAGS="`dnet-config --libs 2>/dev/null`"
fi

AC_ARG_WITH(netmap_includes,
            [  --with-netmap-includes=DIR    netmap include directory],
            [with_netmap_includes="$withval"], [with_netmap_includes="no"])

if test "x$with_netmap_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_netmap_includes}"
fi

AC_ARG_WITH(dpdk_includes,
            [  --with-dpdk-includes=DIR    dpdk include directory],
            [with_dpdk_includes="$withval"], [with_dpdk_includes="no"])

if test "x$with_dpdk_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_dpdk_includes} -include ${with_dpdk_includes}/rte_config.h"
fi

AC_ARG_WITH(dpdk_libraries,
            [  --with-dpdk-libraries=DIR    dpdk library directory],
            [with_dpdk_libraries="$withval"], [with_dpdk_libraries="no"])

if test "x$with_dpdk_libraries" != "xno"; then
    DPDK_LDDIR="-L${with_dpdk_libraries}"
    DPDK_LDFLAGS="-L/home/student/sources/dpdk/x86_64-native-linuxapp-gcc/lib -Wl,-lrte_flow_classify -Wl,--whole-archive -Wl,-lrte_pipeline -Wl,--no-whole-archive -Wl,--whole-archive -Wl,-lrte_table -Wl,--no-whole-archive -Wl,--whole-archive -Wl,-lrte_port -Wl,--no-whole-archive -Wl,-lrte_pdump -Wl,-lrte_distributor -Wl,-lrte_ip_frag -Wl,-lrte_meter -Wl,-lrte_lpm -Wl,--whole-archive -Wl,-lrte_acl -Wl,--no-whole-archive -Wl,-lrte_jobstats -Wl,-lrte_metrics -Wl,-lrte_bitratestats -Wl,-lrte_latencystats -Wl,-lrte_power -Wl,-lrte_efd -Wl,-lrte_bpf -Wl,--whole-archive -Wl,-lrte_cfgfile -Wl,-lrte_gro -Wl,-lrte_gso -Wl,-lrte_hash -Wl,-lrte_member -Wl,-lrte_vhost -Wl,-lrte_kvargs -Wl,-lrte_mbuf -Wl,-lrte_net -Wl,-lrte_ethdev -Wl,-lrte_bbdev -Wl,-lrte_cryptodev -Wl,-lrte_security -Wl,-lrte_compressdev -Wl,-lrte_eventdev -Wl,-lrte_rawdev -Wl,-lrte_timer -Wl,-lrte_mempool -Wl,-lrte_mempool_ring -Wl,-lrte_ring -Wl,-lrte_pci -Wl,-lrte_eal -Wl,-lrte_cmdline -Wl,-lrte_reorder -Wl,-lrte_sched -Wl,-lrte_kni -Wl,-lrte_common_cpt -Wl,-lrte_common_octeontx -Wl,-lrte_common_dpaax -Wl,-lrte_bus_pci -Wl,-lrte_bus_vdev -Wl,-lrte_bus_dpaa -Wl,-lrte_bus_fslmc -Wl,-lrte_mempool_bucket -Wl,-lrte_mempool_stack -Wl,-lrte_mempool_dpaa -Wl,-lrte_mempool_dpaa2 -Wl,-lrte_pmd_af_packet -Wl,-lrte_pmd_ark -Wl,-lrte_pmd_atlantic -Wl,-lrte_pmd_avf -Wl,-lrte_pmd_avp -Wl,-lrte_pmd_axgbe -Wl,-lrte_pmd_bnxt -Wl,-lrte_pmd_bond -Wl,-lrte_pmd_cxgbe -Wl,-lrte_pmd_dpaa -Wl,-lrte_pmd_dpaa2 -Wl,-lrte_pmd_e1000 -Wl,-lrte_pmd_ena -Wl,-lrte_pmd_enetc -Wl,-lrte_pmd_enic -Wl,-lrte_pmd_fm10k -Wl,-lrte_pmd_failsafe -Wl,-lrte_pmd_i40e -Wl,-lrte_pmd_ixgbe -Wl,-lrte_pmd_kni -Wl,-lrte_pmd_lio -Wl,-lrte_pmd_nfp -Wl,-lrte_pmd_null -Wl,-lrte_pmd_qede -Wl,-lrte_pmd_ring -Wl,-lrte_pmd_softnic -Wl,-lrte_pmd_sfc_efx -Wl,-lrte_pmd_tap -Wl,-lrte_pmd_thunderx_nicvf -Wl,-lrte_pmd_vdev_netvsc -Wl,-lrte_pmd_virtio -Wl,-lrte_pmd_vhost -Wl,-lrte_pmd_ifc -Wl,-lrte_pmd_vmxnet3_uio -Wl,-lrte_bus_vmbus -Wl,-lrte_pmd_netvsc -Wl,-lrte_pmd_bbdev_null -Wl,-lrte_pmd_null_crypto -Wl,-lrte_pmd_octeontx_crypto -Wl,-lrte_pmd_crypto_scheduler -Wl,-lrte_pmd_dpaa2_sec -Wl,-lrte_pmd_dpaa_sec -Wl,-lrte_pmd_caam_jr -Wl,-lrte_pmd_virtio_crypto -Wl,-lrte_pmd_octeontx_zip -Wl,-lrte_pmd_qat -Wl,-lrte_pmd_skeleton_event -Wl,-lrte_pmd_sw_event -Wl,-lrte_pmd_dsw_event -Wl,-lrte_pmd_octeontx_ssovf -Wl,-lrte_pmd_dpaa_event -Wl,-lrte_pmd_dpaa2_event -Wl,-lrte_mempool_octeontx -Wl,-lrte_pmd_octeontx -Wl,-lrte_pmd_opdl_event -Wl,-lrte_pmd_skeleton_rawdev -Wl,-lrte_pmd_dpaa2_cmdif -Wl,-lrte_pmd_dpaa2_qdma -Wl,-lrte_bus_ifpga -Wl,-lrte_pmd_ifpga_rawdev -Wl,--no-whole-archive -Wl,-lrt -Wl,-lm -Wl,-lnuma -Wl,-ldl"
fi

AC_ARG_WITH(netvm_includes,
            [  --with-netvm-includes=DIR    netvm include directory],
            [with_netvm_includes="$withval"], [with_netvm_includes="no"])

if test "x$with_netvm_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_netvm_includes}/onvm_nflib -I${with_netvm_includes}/lib"
fi

AC_ARG_WITH(netvm_libraries,
            [  --with-netvm-libraries=DIR    netvm library directory],
            [with_netvm_libraries="$withval"], [with_netvm_libraries="no"])

if test "x$with_netvm_libraries" != "xno"; then
    NETVM_LDFLAGS="-L${with_netvm_libraries}/onvm_nflib/${DPDK_TARGET}/"
    NETVM_HELPER_LDFLAGS="-L${with_netvm_libraries}/lib/${DPDK_TARGET}/"
fi

DEFAULT_ENABLE=yes

# Modules configuration
AC_ARG_ENABLE(bundled-modules,
              AC_HELP_STRING([--disable-bundled-modules],[don't build any of the bundled DAQ modules by default]),
              [], [disable_bundled_modules=no])

if test "$disable_bundled_modules" = no; then
    DEFAULT_ENABLE=yes
else
    DEFAULT_ENABLE=no
fi

# AFPacket Module
AC_ARG_ENABLE(afpacket-module,
              AC_HELP_STRING([--disable-afpacket-module],[don't build the bundled AFPacket module]),
              [enable_afpacket_module="$enableval"], [enable_afpacket_module="$DEFAULT_ENABLE"])
if test "$enable_afpacket_module" = yes; then
    AC_CHECK_HEADERS([linux/if_ether.h linux/if_packet.h], [], [enable_afpacket_module=no])
    AC_CHECK_DECLS([TPACKET2_HDRLEN, PACKET_TX_RING], [], [enable_afpacket_module=no], [[#include <linux/if_packet.h>]])
    if test "$enable_afpacket_module" = yes; then
        STATIC_LIBS="${STATIC_LIBS} -lsfbpf"
    fi
fi
AM_CONDITIONAL([BUILD_AFPACKET_MODULE], [test "$enable_afpacket_module" = yes])

# DPDK Module
AC_ARG_ENABLE(dpdk-module,
              AC_HELP_STRING([--disable-dpdk-module],[don't build the bundled dpdk module]),
              [enable_dpdk_module="$enableval"], [enable_dpdk_module="$DEFAULT_ENABLE"])
if test "$enable_dpdk_module" = yes; then
    AC_CHECK_HEADER([rte_config.h], [], [enable_dpdk_module=no])
    if test "$enable_dpdk_module" = yes; then
        STATIC_LIBS="${STATIC_LIBS} -lsfbpf ${DPDK_LDDIR} ${DPDK_LDFLAGS} -lpthread -lnuma"
        CFLAGS="${CFLAGS} -std=gnu99 -Wno-pedantic"
    fi
fi
AM_CONDITIONAL([BUILD_DPDK_MODULE], [test "$enable_dpdk_module" = yes])

# NETVM Module
AC_ARG_ENABLE(netvm-module,
              AC_HELP_STRING([--disable-netvm-module],[don't build the bundled netvm module]),
              [enable_netvm_module="$enableval"], [enable_netvm_module="$DEFAULT_ENABLE"])
if test "$enable_netvm_module" = yes; then
    AC_CHECK_HEADER([rte_config.h], [], [enable_netvm_module=no])
    if test "$enable_netvm_module" = yes; then
        STATIC_LIBS="${STATIC_LIBS} ${NETVM_LDFLAGS} -lonvm  ${NETVM_HELPER_LDFLAGS} -lonvmhelper"
        CFLAGS="${CFLAGS} -std=gnu99 -Wno-pedantic"
    fi
fi
AM_CONDITIONAL([BUILD_NETVM_MODULE], [test "$enable_netvm_module" = yes])

# Dump Module
AC_ARG_ENABLE(dump-module,
              AC_HELP_STRING([--disable-dump-module],[don't build the bundled Dump module]),
              [enable_dump_module="$enableval"], [enable_dump_module="$DEFAULT_ENABLE"])
if test "$enable_dump_module" = yes; then
    AC_CHECK_HEADER([pcap.h], [], [enable_dump_module=no])
    AC_CHECK_LIB([pcap],[pcap_lib_version],,[enable_dump_module="no"],[])
    if test "$enable_dump_module" = yes; then
        STATIC_LIBS="${STATIC_LIBS} -lpcap"
    fi
fi
AM_CONDITIONAL([BUILD_DUMP_MODULE], [test "$enable_dump_module" = yes])

# IPFW Module
AC_ARG_ENABLE(ipfw-module,
              AC_HELP_STRING([--disable-ipfw-module],[don't build the bundled IPFW module]),
              [enable_ipfw_module="$enableval"], [enable_ipfw_module="$DEFAULT_ENABLE"])
if test "$enable_ipfw_module" = yes; then
    STATIC_LIBS="${STATIC_LIBS} -lsfbpf"
fi
AM_CONDITIONAL([BUILD_IPFW_MODULE], [test "$enable_ipfw_module" = yes])

# IPQ Module
AC_ARG_ENABLE(ipq-module,
              AC_HELP_STRING([--disable-ipq-module],[don't build the bundled IPQ module]),
              [enable_ipq_module="$enableval"], [enable_ipq_module="$DEFAULT_ENABLE"])
if test "$enable_ipq_module" = yes; then
    AC_CHECK_HEADERS([netinet/in.h libipq.h], [], [enable_ipq_module=no])
    AC_CHECK_HEADER([linux/netfilter.h], [], [enable_ipq_module=no],
                    [
                        #include <netinet/in.h>
                    ])
    if test "$enable_ipq_module" = yes; then
        STATIC_LIBS="${STATIC_LIBS} -lipq -lsfbpf"
    fi
fi
AM_CONDITIONAL([BUILD_IPQ_MODULE], [test "$enable_ipq_module" = yes])

# NFQ Module
AC_ARG_ENABLE(nfq-module,
              AC_HELP_STRING([--disable-nfq-module],[don't build the bundled NFQ module]),
              [enable_nfq_module="$enableval"], [enable_nfq_module="$DEFAULT_ENABLE"])
if test "$enable_nfq_module" = yes; then
    AC_CHECK_HEADERS([netinet/in.h libnetfilter_queue/libnetfilter_queue.h], [], [enable_nfq_module=no])
    AC_CHECK_HEADER([linux/netfilter.h], [], [enable_nfq_module=no],
                    [
                        #include <netinet/in.h>
                    ])
    if test "$enable_nfq_module" = yes; then
        STATIC_LIBS="${STATIC_LIBS} -lnfnetlink -lnetfilter_queue -lsfbpf"
    fi
fi
AM_CONDITIONAL([BUILD_NFQ_MODULE], [test "$enable_nfq_module" = yes])

# PCAP Module
AC_ARG_ENABLE(pcap-module,
              AC_HELP_STRING([--disable-pcap-module],[don't build the bundled PCAP module]),
              [enable_pcap_module="$enableval"], [enable_pcap_module="$DEFAULT_ENABLE"])
if test "$enable_pcap_module" = yes; then
    AC_CHECK_HEADER([pcap.h], [], [enable_pcap_module=no])
    AC_CHECK_PCAP_VER("1.0.0")
    if test "$enable_pcap_module" = yes; then
        STATIC_LIBS="${STATIC_LIBS} -lpcap"
    fi
fi
AM_CONDITIONAL([BUILD_PCAP_MODULE], [test "$enable_pcap_module" = yes])

# netmap Module
AC_ARG_ENABLE(netmap-module,
              AC_HELP_STRING([--disable-netmap-module],[don't build the bundled netmap module]),
              [enable_netmap_module="$enableval"], [enable_netmap_module="$DEFAULT_ENABLE"])
if test "$enable_netmap_module" = yes; then
    AC_CHECK_HEADERS([net/netmap.h net/netmap_user.h], [], [enable_netmap_module=no], [
                      #include <stdint.h>
                      #include <sys/socket.h>
                      #include <net/if.h>
                      ])
    AC_CHECK_DECL([NETMAP_API], [], [enable_netmap_module=no], [
                   #include <stdint.h>
                   #include <sys/socket.h>
                   #include <net/if.h>
                   #include <net/netmap.h>
                   ])
    if test "$enable_netmap_module" = yes; then
        STATIC_LIBS="${STATIC_LIBS} -lsfbpf"
    fi
fi
AM_CONDITIONAL([BUILD_NETMAP_MODULE], [test "$enable_netmap_module" = yes])

if test "$enable_ipq_module" = yes -o "$enable_nfq_module" = yes ; then
    AC_CHECK_HEADERS(dnet.h,,DNET_H="no")
    AC_CHECK_HEADERS(dumbnet.h,,DUMBNET_H="no")

    if test "x$DNET_H" = "xno" -a "x$DUMBNET_H" = "xno"; then
        echo
        echo "   ERROR!  dnet header not found, go get it from"
        echo "   http://code.google.com/p/libdnet/ or use the --with-dnet-*"
        echo "   options, if you have it installed in an unusual place"
        exit
    fi

    DNET_FOO="${DNET_LDPATH} ${DNET_LDFLAGS}"

    AC_CHECK_LIB(dnet, eth_set, ,[DNET="no"], [${DNET_FOO}])
    AC_CHECK_LIB(dumbnet, eth_set, ,[DUMBNET="no"], [${DNET_FOO}])

    if test "x$DNET" = "xno" -a "x$DUMBNET" = "xno"; then
        echo
        echo "   ERROR!  dnet library not found, go get it from"
        echo "   http://code.google.com/p/libdnet/ or use the --with-dnet-*"
        echo "   options, if you have it installed in an unusual place"
        exit
    fi

    if test "x$DNET_LDFLAGS" = "x" ; then
        if test "x$DNET" = "xno"; then
            DNET_LDFLAGS="${DNET_LDPATH} -ldumbnet"
        else
            DNET_LDFLAGS="${DNET_LDPATH} -ldnet"
        fi
    fi
    #echo "DNET_LDFLAGS=${DNET_LDFLAGS}"
    STATIC_LIBS="${STATIC_LIBS} ${DNET_LDFLAGS}"
fi

AC_SUBST(DNET_LDFLAGS)

AM_CONDITIONAL([BUILD_MODULES], [test "$enable_afpacket_module" = yes -o \
                                      "$enable_dump_module" = yes -o \
                                      "$enable_ipfw_module" = yes -o \
                                      "$enable_ipq_module" = yes -o \
                                      "$enable_nfq_module" = yes -o \
                                      "$enable_pcap_module" = yes])

LIBS=${save_LIBS}

AC_SUBST(STATIC_LIBS)

AC_CHECK_LIB([dl], [dlopen], [LIBDL="-ldl"])

AM_CONDITIONAL([BUILD_SHARED_MODULES], [ test "$enable_shared" = yes ])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h memory.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([gethostbyname getpagesize memset munmap socket strchr strcspn strdup strerror strrchr strstr strtoul])

# Substitutions
AC_SUBST(V_LEX)
AC_SUBST(V_YACC)
AC_SUBST(XCCFLAGS)
AC_SUBST(LIBDL)

AC_CONFIG_FILES([Makefile
                 api/Makefile
                 os-daq-modules/Makefile
                 os-daq-modules/daq-modules-config
                 sfbpf/Makefile])
AC_OUTPUT

echo
echo "Build AFPacket DAQ module.. : $enable_afpacket_module"
echo "Build DPDK DAQ module...... : $enable_dpdk_module"
echo "Build NetVM DAQ module..... : $enable_netvm_module"
echo "Build Dump DAQ module...... : $enable_dump_module"
echo "Build IPFW DAQ module...... : $enable_ipfw_module"
echo "Build IPQ DAQ module....... : $enable_ipq_module"
echo "Build NFQ DAQ module....... : $enable_nfq_module"
echo "Build PCAP DAQ module...... : $enable_pcap_module"
echo "Build netmap DAQ module.... : $enable_netmap_module"
echo
