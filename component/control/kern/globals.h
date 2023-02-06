#include "common.h"
#ifndef __GLOBAL_H
#define __GLOBAL_H

enum { BPF_F_CURRENT_NETNS = -1 };

enum {
  DisableL4ChecksumPolicy_EnableL4Checksum,
  DisableL4ChecksumPolicy_Restore,
  DisableL4ChecksumPolicy_SetZero,
};

// Param keys:
static const __u32 zero_key = 0;
static const __u32 tproxy_port_key = 1;
static const __u32 disable_l4_tx_checksum_key
    __attribute__((unused, deprecated)) = 2;
static const __u32 disable_l4_rx_checksum_key
    __attribute__((unused, deprecated)) = 3;
static const __u32 control_plane_pid_key = 4;

struct ip_port {
  __be32 ip[4];
  __be16 port;
};

struct ip_port_outbound {
  __be32 ip[4];
  __be16 port;
  __u8 outbound;
  __u8 unused;
};

struct tuples {
  struct ip_port src;
  struct ip_port dst;
  __u8 l4proto;
};

/// TODO: Remove items from the dst_map by conntrack.
// Dest map:
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key,
         struct ip_port); // As TCP client side [SYN, !ACK],
                          // (source ip, source port, tcp) is
                          // enough for identifier. And UDP client
                          // side does not care it (full-cone).
  __type(value, struct ip_port_outbound); // Original target.
  __uint(max_entries, MAX_DST_MAPPING_NUM);
  /// NOTICE: It MUST be pinned.
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_dst_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct tuples);
  __type(value, __u32); // outbound
  __uint(max_entries, MAX_DST_MAPPING_NUM);
} routing_tuples_map SEC(".maps");

// Params:
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_PARAM_LEN);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} param_map SEC(".maps");

// LPM key:
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, struct lpm_key);
  __uint(max_entries, 3);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} lpm_key_map SEC(".maps");

// h_sport, h_dport:
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, __u16);
  __uint(max_entries, 2);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} h_port_map SEC(".maps");

// l4proto, ipversion:
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 2);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} l4proto_ipversion_map SEC(".maps");

// IPPROTO to hdr_size
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __s32);
  __uint(max_entries, 5);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipproto_hdrsize_map SEC(".maps");

// Dns upstream:
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct ip_port);
  __uint(max_entries, 1);
} dns_upstream_map SEC(".maps");

// Interface Ips:
struct if_params {
  __be32 ip4[4];
  __be32 ip6[4];

  bool has_ip4;
  bool has_ip6;
  bool rx_cksm_offload;
  bool tx_l4_cksm_ip4_offload;
  bool tx_l4_cksm_ip6_offload;
  bool use_nonstandard_offload_algorithm;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);              // ifindex
  __type(value, struct if_params); // ip
  __uint(max_entries, MAX_INTERFACE_NUM);
  /// NOTICE: No persistence.
  // __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_params_map SEC(".maps");

// Array of LPM tries:
struct lpm_key {
  struct bpf_lpm_trie_key trie_key;
  __be32 data[4];
};
struct map_lpm_type {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, MAX_LPM_SIZE);
  __uint(key_size, sizeof(struct lpm_key));
  __uint(value_size, sizeof(__u32));
} unused_lpm_type SEC(".maps"), host_ip_lpm SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(key_size, sizeof(__u32));
  __uint(max_entries, MAX_LPM_NUM);
  // __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct map_lpm_type);
} lpm_array_map SEC(".maps");

enum __attribute__((packed)) MatchType {
  /// WARNING: MUST SYNC WITH common/consts/ebpf.go.
  MatchType_DomainSet,
  MatchType_IpSet,
  MatchType_SourceIpSet,
  MatchType_Port,
  MatchType_SourcePort,
  MatchType_L4Proto,
  MatchType_IpVersion,
  MatchType_Mac,
  MatchType_ProcessName,
  MatchType_Final,
};
enum L4ProtoType {
  L4ProtoType_TCP = 1,
  L4ProtoType_UDP = 2,
  L4ProtoType_X = 3,
};
enum IpVersionType {
  IpVersionType_4 = 1,
  IpVersionType_6 = 2,
  IpVersionType_X = 3,
};
struct port_range {
  __u16 port_start;
  __u16 port_end;
};

/*
 Rule is like as following:

 domain(geosite:cn, suffix: google.com) && l4proto(tcp) -> my_group

 pseudocode: domain(geosite:cn || suffix:google.com) && l4proto(tcp) -> my_group

 A match_set can be: IP set geosite:cn, suffix google.com, tcp proto
 */
struct match_set {
  union {
    __u8 __value[16]; // Placeholder for bpf2go.

    __u32 index;
    struct port_range port_range;
    enum L4ProtoType l4proto_type;
    enum IpVersionType ip_version;
    __u32 pname[TASK_COMM_LEN / 4];
  };
  bool not ; // A subrule flag (this is not a match_set flag).
  enum MatchType type;
  __u8 outbound; // User-defined value range is [0, 252].
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct match_set);
  __uint(max_entries, MAX_MATCH_SET_LEN);
  // __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_map SEC(".maps");

struct domain_routing {
  __u32 bitmap[MAX_MATCH_SET_LEN / 32];
};
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __be32[4]);
  __type(value, struct domain_routing);
  __uint(max_entries, 65535);
  /// NOTICE: No persistence.
  // __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_routing_map SEC(".maps");

struct ip_port_proto {
  __u32 ip[4];
  __be16 port;
  __u8 proto;
};

struct pid_pname {
  __u32 pid;
  char pname[TASK_COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u64);
  __type(value, struct pid_pname);
  __uint(max_entries, MAX_SRC_PID_PNAME_MAPPING_NUM);
  /// NOTICE: No persistence.
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_pid_map SEC(".maps");

#endif