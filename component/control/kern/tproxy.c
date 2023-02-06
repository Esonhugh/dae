// +build ignore
/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

#include "common.h"

#include "globals.h"

#include "helper.h"

SEC("tc/ingress")
int tproxy_lan_ingress(struct __sk_buff *skb) {
  struct ethhdr ethh;
  struct iphdr iph;
  struct ipv6hdr ipv6h;
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ihl;
  __u8 ipversion;
  __u8 l4proto;
  int ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl,
                            &ipversion, &l4proto);
  if (ret) {
    bpf_printk("parse_transport: %d", ret);
    return TC_ACT_OK;
  }

  // Prepare five tuples.
  struct tuples tuples = {0};
  tuples.l4proto = l4proto;
  if (ipversion == 4) {
    tuples.src.ip[2] = bpf_htonl(0x0000ffff);
    tuples.src.ip[3] = iph.saddr;

    tuples.dst.ip[2] = bpf_htonl(0x0000ffff);
    tuples.dst.ip[3] = iph.daddr;

  } else {
    __builtin_memcpy(tuples.dst.ip, &ipv6h.daddr, IPV6_BYTE_LENGTH);
    __builtin_memcpy(tuples.src.ip, &ipv6h.saddr, IPV6_BYTE_LENGTH);
  }
  if (l4proto == IPPROTO_TCP) {
    tuples.src.port = tcph.source;
    tuples.dst.port = tcph.dest;
  } else {
    tuples.src.port = udph.source;
    tuples.dst.port = udph.dest;
  }

  /**
  ip rule add fwmark 0x80000000/0x80000000 table 2023
  ip route add local default dev lo table 2023
  ip -6 rule add fwmark 0x80000000/0x80000000 table 2023
  ip -6 route add local ::/0 dev lo table 2023

  ip rule del fwmark 0x80000000/0x80000000 table 2023
  ip route del local default dev lo table 2023
  ip -6 rule del fwmark 0x80000000/0x80000000 table 2023
  ip -6 route del local ::/0 dev lo table 2023
  */
  struct bpf_sock_tuple tuple = {0};
  __u32 tuple_size;
  struct bpf_sock *sk;
  bool is_old_conn;
  __u32 flag[6] = {0};
  void *l4hdr;

  // Socket lookup and assign skb to existing socket connection.
  if (ipversion == 4) {
    tuple.ipv4.daddr = tuples.dst.ip[3];
    tuple.ipv4.saddr = tuples.src.ip[3];
    tuple.ipv4.dport = tuples.dst.port;
    tuple.ipv4.sport = tuples.src.port;
    tuple_size = sizeof(tuple.ipv4);
  } else {
    __builtin_memcpy(tuple.ipv6.daddr, tuples.dst.ip, IPV6_BYTE_LENGTH);
    __builtin_memcpy(tuple.ipv6.saddr, tuples.src.ip, IPV6_BYTE_LENGTH);
    tuple.ipv6.dport = tuples.dst.port;
    tuple.ipv6.sport = tuples.src.port;
    tuple_size = sizeof(tuple.ipv6);
  }

  if (l4proto == IPPROTO_TCP) {
    // TCP.
    if (tcph.syn && !tcph.ack) {
      goto new_connection;
    }

    sk = bpf_skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
    if (sk) {
      if (sk->state != BPF_TCP_LISTEN) {
        is_old_conn = true;
        goto assign;
      }
      bpf_sk_release(sk);
    }
  } else {
    // UDP.

    sk = bpf_sk_lookup_udp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
    if (sk) {
      is_old_conn = true;
      goto assign;
    }
  }

// Routing for new connection.
new_connection:
  if (l4proto == IPPROTO_TCP) {
    if (!(tcph.syn && !tcph.ack)) {
      // Not a new TCP connection.
      // Perhaps single-arm.
      return TC_ACT_OK;
    }
    l4hdr = &tcph;
    flag[0] = L4ProtoType_TCP;
  } else {
    l4hdr = &udph;
    flag[0] = L4ProtoType_UDP;
  }
  if (ipversion == 4) {
    flag[1] = IpVersionType_4;
  } else {
    flag[1] = IpVersionType_6;
  }
  __be32 mac[4] = {
      0,
      0,
      bpf_htonl((ethh.h_source[0] << 8) + (ethh.h_source[1])),
      bpf_htonl((ethh.h_source[2] << 24) + (ethh.h_source[3] << 16) +
                (ethh.h_source[4] << 8) + (ethh.h_source[5])),
  };
  if ((ret = routing(flag, l4hdr, tuples.src.ip, tuples.dst.ip, mac)) < 0) {
    bpf_printk("shot routing: %d", ret);
    return TC_ACT_SHOT;
  }
  __u32 outbound = ret;
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
  if (l4proto == IPPROTO_TCP) {
    bpf_printk("tcp(lan): outbound: %u, target: %pI6:%u", outbound,
               tuples.dst.ip, bpf_ntohs(tuples.dst.port));
  } else {
    bpf_printk("udp(lan): outbound: %u, target: %pI6:%u", outbound,
               tuples.dst.ip, bpf_ntohs(tuples.dst.port));
  }
#endif
  if (outbound == OUTBOUND_DIRECT) {
    goto direct;
  } else if (unlikely(outbound == OUTBOUND_BLOCK)) {
    goto block;
  }

  // Save routing result.
  if ((ret = bpf_map_update_elem(&routing_tuples_map, &tuples, &outbound,
                                 BPF_ANY))) {
    bpf_printk("shot save routing result: %d", ret);
    return TC_ACT_SHOT;
  }

  // Assign to control plane.
  __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
  if (!tproxy_port) {
    bpf_printk("shot tproxy port not set: %d", ret);
    return TC_ACT_SHOT;
  }
  __builtin_memset(&tuple, 0, sizeof(tuple));
  tuple.ipv6.daddr[3] = bpf_htonl(0x00000001);
  tuple.ipv6.dport = *tproxy_port;

  if (l4proto == IPPROTO_TCP) {
    // TCP.

    sk = bpf_skc_lookup_tcp(skb, &tuple, sizeof(tuple), BPF_F_CURRENT_NETNS, 0);
    if (!sk || sk->state != BPF_TCP_LISTEN) {
      bpf_printk("shot tproxy not listen: %d", ret);
      goto sk_shot;
    }
  } else {
    // UDP.

    sk = bpf_sk_lookup_udp(skb, &tuple, sizeof(tuple), BPF_F_CURRENT_NETNS, 0);
    if (!sk) {
      goto sk_shot;
    }
  }

assign:
  skb->mark = TPROXY_MARK;
  ret = bpf_sk_assign(skb, sk, 0);
  bpf_sk_release(sk);
  if (ret) {
    if (is_old_conn && ret == -ESOCKTNOSUPPORT) {
      bpf_printk("bpf_sk_assign: %d, perhaps you have other TPROXY programs "
                 "(such as v2ray) running?",
                 ret);
    } else {
      bpf_printk("bpf_sk_assign: %d", ret);
    }
    return TC_ACT_SHOT;
  }
  return TC_ACT_OK;

sk_shot:
  if (sk) {
    bpf_sk_release(sk);
  }
  return TC_ACT_SHOT;

direct:
  return TC_ACT_OK;

block:
  return TC_ACT_SHOT;
}


__u8 special_mac_to_tproxy[6] = {2, 0, 2, 3, 0, 0};
__u8 special_mac_from_tproxy[6] = {2, 0, 2, 3, 0, 1};


// Routing and redirect the packet back.
// We cannot modify the dest address here. So we cooperate with wan_ingress.
SEC("tc/wan_egress")
int tproxy_wan_egress(struct __sk_buff *skb) {
  // Skip packets not from localhost.
  if (skb->ingress_ifindex != NOWHERE_IFINDEX) {
    return TC_ACT_OK;
  }
  // if ((skb->mark & 0x80) == 0x80) {
  //   return TC_ACT_OK;
  // }

  struct ethhdr ethh;
  struct iphdr iph;
  struct ipv6hdr ipv6h;
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ihl;
  __u8 ipversion;
  __u8 l4proto;
  bool tcp_state_syn;
  int ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl,
                            &ipversion, &l4proto);
  if (ret) {
    return TC_ACT_OK;
  }

  __be16 sport;
  if (l4proto == IPPROTO_TCP) {
    sport = tcph.source;
  } else if (l4proto == IPPROTO_UDP) {
    sport = udph.source;
  } else {
    return TC_ACT_OK;
  }

  // We should know if this packet is from tproxy.
  // We do not need to check the source ip because we have skipped packets not
  // from localhost.
  __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
  if (!tproxy_port) {
    return TC_ACT_OK;
  }
  bool tproxy_response = *tproxy_port == sport;

  // Backup for further use.
  __be16 ipv4_tot_len = 0;

  // Parse saddr and daddr as ipv6 format.
  __be32 saddr[4];
  __be32 daddr[4];
  if (ipversion == 4) {
    saddr[0] = 0;
    saddr[1] = 0;
    saddr[2] = bpf_htonl(0x0000ffff);
    saddr[3] = iph.saddr;

    daddr[0] = 0;
    daddr[1] = 0;
    daddr[2] = bpf_htonl(0x0000ffff);
    daddr[3] = iph.daddr;

    ipv4_tot_len = iph.tot_len;
  } else {
    __builtin_memcpy(daddr, &ipv6h.daddr, IPV6_BYTE_LENGTH);
    __builtin_memcpy(saddr, &ipv6h.saddr, IPV6_BYTE_LENGTH);
  }

  if (tproxy_response) {
    // Packets from tproxy port.
    // We need to redirect it to original port.

    // Write mac.
    if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
                                   ethh.h_source, sizeof(ethh.h_source), 0))) {
      return TC_ACT_SHOT;
    }
    if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
                                   special_mac_from_tproxy,
                                   sizeof(ethh.h_source), 0))) {
      return TC_ACT_SHOT;
    };
  } else {
    // Normal packets.

    if (l4proto == IPPROTO_TCP) {
      // Backup for further use.
      tcp_state_syn = tcph.syn && !tcph.ack;
      struct ip_port key_src;
      __builtin_memset(&key_src, 0, sizeof(key_src));
      // Use daddr as key in WAN because tproxy (control plane) also lookups the
      // map element using income client ip (that is daddr).
      __builtin_memcpy(key_src.ip, daddr, IPV6_BYTE_LENGTH);
      key_src.port = tcph.source;
      __u8 outbound;
      if (unlikely(tcp_state_syn)) {
        // New TCP connection.
        // bpf_printk("[%X]New Connection", bpf_ntohl(tcph.seq));
        __u32 flag[6] = {L4ProtoType_TCP}; // TCP
        if (ipversion == 6) {
          flag[1] = IpVersionType_6;
        } else {
          flag[1] = IpVersionType_4;
        }
        struct pid_pname *pid_pname;
        if (pid_is_control_plane(skb, &pid_pname)) {
          // From control plane. Direct.
          return TC_ACT_OK;
        }
        if (pid_pname) {
          __builtin_memcpy(&flag[2], pid_pname->pname, TASK_COMM_LEN);
        }
        __be32 mac[4] = {
            0,
            0,
            bpf_htonl((ethh.h_source[0] << 8) + (ethh.h_source[1])),
            bpf_htonl((ethh.h_source[2] << 24) + (ethh.h_source[3] << 16) +
                      (ethh.h_source[4] << 8) + (ethh.h_source[5])),
        };
        if ((ret = routing(flag, &tcph, saddr, daddr, mac)) < 0) {
          bpf_printk("shot routing: %d", ret);
          return TC_ACT_SHOT;
        }

        outbound = ret;

#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
        // Print only new connection.
        bpf_printk("tcp(wan): outbound: %u, %pI6:%u", outbound, daddr,
                   bpf_ntohs(key_src.port));
#endif
      } else {
        // bpf_printk("[%X]Old Connection", bpf_ntohl(tcph.seq));
        // The TCP connection exists.
        struct ip_port_outbound *dst =
            bpf_map_lookup_elem(&tcp_dst_map, &key_src);
        if (!dst) {
          // Do not impact previous connections.
          return TC_ACT_OK;
        }
        outbound = dst->outbound;
      }

      if (outbound == OUTBOUND_DIRECT) {
        return TC_ACT_OK;
      } else if (unlikely(outbound == OUTBOUND_BLOCK)) {
        return TC_ACT_SHOT;
      }
      // Rewrite to control plane.

      if (unlikely(tcp_state_syn)) {
        struct ip_port_outbound value_dst;
        __builtin_memset(&value_dst, 0, sizeof(value_dst));
        __builtin_memcpy(value_dst.ip, daddr, IPV6_BYTE_LENGTH);
        value_dst.port = tcph.dest;
        value_dst.outbound = outbound;
        // bpf_printk("UPDATE: %pI6:%u", key_src.ip, bpf_ntohs(key_src.port));
        bpf_map_update_elem(&tcp_dst_map, &key_src, &value_dst, BPF_ANY);
      }

      // Write mac.
      if ((ret =
               bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
                                   ethh.h_source, sizeof(ethh.h_source), 0))) {
        return TC_ACT_SHOT;
      }
      if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
                                     special_mac_to_tproxy,
                                     sizeof(ethh.h_source), 0))) {
        return TC_ACT_SHOT;
      };

    } else if (l4proto == IPPROTO_UDP) {
      // Backup for further use.
      struct ip_port_outbound new_hdr;
      __builtin_memset(&new_hdr, 0, sizeof(new_hdr));
      __builtin_memcpy(new_hdr.ip, daddr, IPV6_BYTE_LENGTH);
      new_hdr.port = udph.dest;

      // Routing. It decides if we redirect traffic to control plane.
      __u32 flag[6] = {L4ProtoType_UDP};
      if (ipversion == 6) {
        flag[1] = IpVersionType_6;
      } else {
        flag[1] = IpVersionType_4;
      }
      struct pid_pname *pid_pname;
      if (pid_is_control_plane(skb, &pid_pname)) {
        // From control plane. Direct.
        return TC_ACT_OK;
      }
      if (pid_pname) {
        __builtin_memcpy(&flag[2], pid_pname->pname, TASK_COMM_LEN);
      }
      __be32 mac[4] = {
          0,
          0,
          bpf_htonl((ethh.h_source[0] << 8) + (ethh.h_source[1])),
          bpf_htonl((ethh.h_source[2] << 24) + (ethh.h_source[3] << 16) +
                    (ethh.h_source[4] << 8) + (ethh.h_source[5])),
      };
      if ((ret = routing(flag, &udph, saddr, daddr, mac)) < 0) {
        bpf_printk("shot routing: %d", ret);
        return TC_ACT_SHOT;
      }
      new_hdr.outbound = ret;
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
      bpf_printk("udp(wan): outbound: %u, %pI6:%u", new_hdr.outbound, daddr,
                 bpf_ntohs(new_hdr.port));
#endif

      if (new_hdr.outbound == OUTBOUND_DIRECT) {
        return TC_ACT_OK;
      } else if (unlikely(new_hdr.outbound == OUTBOUND_BLOCK)) {
        return TC_ACT_SHOT;
      }

      // Rewrite to control plane.

      // Write mac.
      if ((ret =
               bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
                                   ethh.h_source, sizeof(ethh.h_source), 0))) {
        return TC_ACT_SHOT;
      }
      if ((ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
                                     special_mac_to_tproxy,
                                     sizeof(ethh.h_source), 0))) {
        return TC_ACT_SHOT;
      };

      bool disable_l4_checksum = wan_disable_checksum(skb->ifindex, ipversion);
      // Encap a header to transmit fullcone tuple.
      if ((ret = encap_after_udp_hdr(skb, ipversion, ihl, ipv4_tot_len,
                                     &new_hdr, sizeof(new_hdr),
                                     // It is a part of ingress link.
                                     !disable_l4_checksum))) {
        return TC_ACT_SHOT;
      }
    }
  }

  // // Print packet in hex for debugging (checksum or something else).
  // if ((l4proto == IPPROTO_TCP ? tcph.dest : udph.dest) == bpf_htons(8443)) {
  //   bpf_printk("PRINT OUTPUT PACKET");
  //   for (__u32 i = 0; i < skb->len && i < 500; i++) {
  //     __u8 t = 0;
  //     bpf_skb_load_bytes(skb, i, &t, 1);
  //     bpf_printk("%02x", t);
  //   }
  // }

  // Redirect from egress to ingress.
  if ((ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS)) == TC_ACT_SHOT) {
    bpf_printk("Shot bpf_redirect: %d", ret);
    return TC_ACT_SHOT;
  }
  return TC_ACT_REDIRECT;
}

SEC("tc/wan_ingress")
int tproxy_wan_ingress(struct __sk_buff *skb) {
  struct ethhdr ethh;
  struct iphdr iph;
  struct ipv6hdr ipv6h;
  struct tcphdr tcph;
  struct udphdr udph;
  __u8 ihl;
  __u8 ipversion;
  __u8 l4proto;
  int ret = parse_transport(skb, &ethh, &iph, &ipv6h, &tcph, &udph, &ihl,
                            &ipversion, &l4proto);
  if (ret) {
    return TC_ACT_OK;
  }

  // bpf_printk("bpf_ntohs(*(__u16 *)&ethh.h_source[4]): %u",
  //            bpf_ntohs(*(__u16 *)&ethh.h_source[4]));
  // Tproxy related.
  __u16 tproxy_typ = bpf_ntohs(*(__u16 *)&ethh.h_source[4]);
  if (*(__u32 *)&ethh.h_source[0] != bpf_htonl(0x02000203) || tproxy_typ > 1) {
    return TC_ACT_OK;
  }
  bool tproxy_response = tproxy_typ == 1;

  // Parse saddr and daddr as ipv6 format.
  __be32 saddr[4];
  __be32 daddr[4];
  __be32 ipv4_tot_len = 0;
  if (ipversion == 4) {
    saddr[0] = 0;
    saddr[1] = 0;
    saddr[2] = bpf_htonl(0x0000ffff);
    saddr[3] = iph.saddr;

    daddr[0] = 0;
    daddr[1] = 0;
    daddr[2] = bpf_htonl(0x0000ffff);
    daddr[3] = iph.daddr;

    ipv4_tot_len = iph.tot_len;
  } else {
    __builtin_memcpy(daddr, &ipv6h.daddr, IPV6_BYTE_LENGTH);
    __builtin_memcpy(saddr, &ipv6h.saddr, IPV6_BYTE_LENGTH);
  }
  __be16 sport;
  __be16 dport;
  if (l4proto == IPPROTO_TCP) {
    sport = tcph.source;
    dport = tcph.dest;
  } else if (l4proto == IPPROTO_UDP) {
    sport = udph.source;
    dport = udph.dest;
  } else {
    return TC_ACT_OK;
  }

  bool disable_l4_checksum = wan_disable_checksum(skb->ifindex, ipversion);

  // // Print packet in hex for debugging (checksum or something else).
  // if (dport == bpf_htons(8443)) {
  //   bpf_printk("PRINT BEFORE PACKET");
  //   for (__u32 i = 0; i < skb->len && i < 500; i++) {
  //     __u8 t = 0;
  //     bpf_skb_load_bytes(skb, i, &t, 1);
  //     bpf_printk("%02x", t);
  //   }
  // }
  if (tproxy_response) {
    // Send the tproxy response packet to origin.

    // If a client sent a packet at the begining, let's say the client is
    // sender and its ip is right host ip.
    // saddr is host ip and right sender ip.
    // Now when tproxy responses, dport is sender's sport. See (1) below. daddr
    // is original dest ip (target address).

    // bpf_printk("[%u]should send to origin: %pI6:%u",
    // l4proto, saddr,
    //            bpf_ntohs(dport));

    if (l4proto == IPPROTO_TCP) {
      // Lookup original dest as sip and sport.
      struct ip_port key_dst;
      __builtin_memset(&key_dst, 0, sizeof(key_dst));
      // Use daddr as key in WAN because tproxy (control plane) also lookups the
      // map element using income client ip (that is daddr).
      __builtin_memcpy(key_dst.ip, daddr, IPV6_BYTE_LENGTH);
      key_dst.port = tcph.dest;
      struct ip_port_outbound *original_dst =
          bpf_map_lookup_elem(&tcp_dst_map, &key_dst);
      if (!original_dst) {
        bpf_printk("[%X]Bad Connection: to: %pI6:%u", bpf_ntohl(tcph.seq),
                   key_dst.ip, bpf_ntohs(key_dst.port));
        // Do not impact previous connections.
        return TC_ACT_SHOT;
      }

      // Rewrite sip and sport.
      if ((ret = rewrite_ip(skb, ipversion, IPPROTO_TCP, ihl, saddr,
                            original_dst->ip, false, !disable_l4_checksum))) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }
      if ((ret = rewrite_port(skb, IPPROTO_TCP, ihl, sport, original_dst->port,
                              false, !disable_l4_checksum))) {
        bpf_printk("Shot Port: %d", ret);
        return TC_ACT_SHOT;
      }
    } else if (l4proto == IPPROTO_UDP) {

      /// NOTICE: Actually, we do not need symmetrical headers in client and
      /// server. We use it for convinience. This behavior may change in the
      /// future. Outbound here is useless and redundant.
      struct ip_port_outbound ori_src;

      // Get source ip/port from our packet header.

      // Decap header to get fullcone tuple.
      if ((ret =
               decap_after_udp_hdr(skb, ipversion, ihl, ipv4_tot_len, &ori_src,
                                   sizeof(ori_src), !disable_l4_checksum))) {
        return TC_ACT_SHOT;
      }

      // Rewrite udp src ip
      if ((ret = rewrite_ip(skb, ipversion, IPPROTO_UDP, ihl, saddr, ori_src.ip,
                            false, !disable_l4_checksum))) {
        bpf_printk("Shot IP: %d", ret);
        return TC_ACT_SHOT;
      }

      // Rewrite udp src port
      if ((ret = rewrite_port(skb, IPPROTO_UDP, ihl, sport, ori_src.port, false,
                              !disable_l4_checksum))) {
        bpf_printk("Shot Port: %d", ret);
        return TC_ACT_SHOT;
      }

      // bpf_printk("real from: %pI4:%u", &ori_src.ip, bpf_ntohs(ori_src.port));

      // Print packet in hex for debugging (checksum or something else).
      // bpf_printk("UDP EGRESS OK");
      // for (__u32 i = 0; i < skb->len && i < 1500; i++) {
      //   __u8 t = 0;
      //   bpf_skb_load_bytes(skb, i, &t, 1);
      //   bpf_printk("%02x", t);
      // }
    }
    // Rewrite dip to host ip.
    if ((ret = rewrite_ip(skb, ipversion, l4proto, ihl, daddr, saddr, true,
                          !disable_l4_checksum))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }
  } else {
    // Should send the packet to tproxy.

    // Get tproxy ip and port.
    // saddr should be tproxy ip.
    __be32 *tproxy_ip = saddr;
    // __builtin_memcpy(tproxy_ip, saddr, sizeof(tproxy_ip));
    __be16 *tproxy_port = bpf_map_lookup_elem(&param_map, &tproxy_port_key);
    if (!tproxy_port) {
      return TC_ACT_OK;
    }
    // bpf_printk("should send to: %pI6:%u", tproxy_ip,
    // bpf_ntohs(*tproxy_port));

    if ((ret = rewrite_ip(skb, ipversion, l4proto, ihl, daddr, tproxy_ip, true,
                          !disable_l4_checksum))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }

    // Rewrite dst port.
    if ((ret = rewrite_port(skb, l4proto, ihl, dport, *tproxy_port, true,
                            !disable_l4_checksum))) {
      bpf_printk("Shot Port: %d", ret);
      return TC_ACT_SHOT;
    }

    // (1) Use daddr as saddr to pass NIC verification. Notice that we do not
    // modify the <sport> so tproxy will send packet to it.
    if ((ret = rewrite_ip(skb, ipversion, l4proto, ihl, saddr, daddr, false,
                          !disable_l4_checksum))) {
      bpf_printk("Shot IP: %d", ret);
      return TC_ACT_SHOT;
    }
  }

  // // Print packet in hex for debugging (checksum or something else).
  // if (dport == bpf_htons(8443)) {
  //   bpf_printk("PRINT AFTER PACKET");
  //   for (__u32 i = 0; i < skb->len && i < 500; i++) {
  //     __u8 t = 0;
  //     bpf_skb_load_bytes(skb, i, &t, 1);
  //     bpf_printk("%02x", t);
  //   }
  // }
  if (disable_l4_checksum) {
    __u32 l4_cksm_off = l4_checksum_off(l4proto, ihl);
    // Set checksum zero.
    __sum16 bak_cksm = 0;
    bpf_skb_store_bytes(skb, l4_cksm_off, &bak_cksm, sizeof(bak_cksm), 0);
    bpf_csum_level(skb, BPF_CSUM_LEVEL_RESET);
  }

  return TC_ACT_OK;
}



// Create cookie to pid, pname mapping.
SEC("cgroup/sock_create")
int tproxy_wan_cg_sock_create(struct bpf_sock *sk) {
  update_map_elem_by_cookie(bpf_get_socket_cookie(sk));
  return 1;
}
// Remove cookie to pid, pname mapping.
SEC("cgroup/sock_release")
int tproxy_wan_cg_sock_release(struct bpf_sock *sk) {
  __u64 cookie = bpf_get_socket_cookie(sk);
  if (unlikely(!cookie)) {
    bpf_printk("zero cookie");
    return 1;
  }
  bpf_map_delete_elem(&cookie_pid_map, &cookie);
  return 1;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
