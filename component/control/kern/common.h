#ifndef __COMMON_H
#define __COMMON_H
#include <asm-generic/errno-base.h>

#include "headers/if_ether_defs.h"
#include "headers/pkt_cls_defs.h"
#include "headers/socket_defs.h"
#include "headers/vmlinux.h"

// #include <bpf/bpf_core_read.h>
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_probe_read.h"

// #define __DEBUG_ROUTING
// #define __PRINT_ROUTING_RESULT
// #define __REMOVE_BPF_PRINTK

#ifdef __REMOVE_BPF_PRINTK
#undef bpf_printk
#define bpf_printk(...) (void)0
#endif

// #define likely(x) x
// #define unlikely(x) x
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#define IPV6_BYTE_LENGTH 16
#define TASK_COMM_LEN 16

#define IPV4_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IPV4_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IPV4_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IPV6_DST_OFF (ETH_HLEN + offsetof(struct ipv6hdr, daddr))
#define IPV6_SRC_OFF (ETH_HLEN + offsetof(struct ipv6hdr, saddr))

#define NOWHERE_IFINDEX 0
#define LOOPBACK_IFINDEX 1
#define LOOPBACK_ADDR 0x7f000001

#define MAX_PARAM_LEN 16
#define MAX_INTERFACE_NUM 128
#define MAX_MATCH_SET_LEN (32 * 3)
#define MAX_LPM_SIZE 20480
//#define MAX_LPM_SIZE 20480
#define MAX_LPM_NUM (MAX_MATCH_SET_LEN + 8)
#define MAX_DST_MAPPING_NUM (65536 * 2)
#define MAX_SRC_PID_PNAME_MAPPING_NUM (65536)
#define IPV6_MAX_EXTENSIONS 4
#define MAX_ARG_LEN_TO_PROBE 192
#define MAX_ARG_SCANNER_BUFFER_SIZE (TASK_COMM_LEN * 4)

#define OUTBOUND_DIRECT 0
#define OUTBOUND_BLOCK 1
#define OUTBOUND_CONTROL_PLANE_DIRECT 0xFD
#define OUTBOUND_LOGICAL_OR 0xFE
#define OUTBOUND_LOGICAL_AND 0xFF
#define OUTBOUND_LOGICAL_MASK 0xFE

#define TPROXY_MARK 0x80000000

#define ESOCKTNOSUPPORT 94 /* Socket type not supported */

#endif