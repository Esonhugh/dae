#include "common.h"
#include "globals.h"
#ifndef __HELPER_H
#define __HELPER_H


// Functions:

// equal16: compare two ipv6 addresses
static __always_inline bool equal16(const __be32 x[4], const __be32 y[4]) {
#if __clang_major__ >= 10
  return ((__be64 *)x)[0] == ((__be64 *)y)[0] &&
         ((__be64 *)x)[1] == ((__be64 *)y)[1];
#else
  return __builtin_bcmp(x, y, IPV6_BYTE_LENGTH) == 0;
#endif
}

// l4_checksum_rel_off: get the offset of the l4 checksum relative to the protocol
static __always_inline __u32 l4_checksum_rel_off(__u8 proto) {
  switch (proto) {
  case IPPROTO_TCP:
    return offsetof(struct tcphdr, check);

  case IPPROTO_UDP:
    return offsetof(struct udphdr, check);
  }
  return 0;
}

// l4_checksum_off : get the offset of the l4 checksum relative to the start of the packet
static __always_inline __u32 l4_checksum_off(__u8 proto, __u8 ihl) {
  return ETH_HLEN + ihl * 4 + l4_checksum_rel_off(proto);
}

// bpf_update_offload_l4cksm_32: update the l4 checksum when the l4 header is 32-bit aligned
static __always_inline int bpf_update_offload_l4cksm_32(struct __sk_buff *skb,
                                                        __u32 l4_cksm_off,
                                                        __be32 old,
                                                        __be32 new)
{
  int ret;
  __sum16 cksm;
  if ((ret = bpf_skb_load_bytes(skb, l4_cksm_off, &cksm, sizeof(cksm)))) {
    return ret;
  }
  //  bpf_printk("before: %x", bpf_ntohs(cksm));
  cksm =
      bpf_htons(bpf_ntohs(cksm) + bpf_ntohs(*(__be16 *)&new) +
                bpf_ntohs(*((__be16 *)&new + 1)) - bpf_ntohs(*(__be16 *)&old) -
                bpf_ntohs(*((__be16 *)&old + 1)));
  if ((ret = bpf_skb_store_bytes(skb, l4_cksm_off, &cksm, sizeof(cksm), 0))) {
    return ret;
  }
  //  bpf_printk("after: %x", bpf_ntohs(cksm));
  return 0;
}

// bpf_update_offload_l4cksm_16: update the l4 checksum when the l4 header is 16-bit aligned
static __always_inline int bpf_update_offload_l4cksm_16(struct __sk_buff *skb,
                                                        __u32 l4_cksm_off,
                                                        __be16 old,
                                                        __be16 new)
{
  int ret;
  __sum16 cksm;
  if ((ret = bpf_skb_load_bytes(skb, l4_cksm_off, &cksm, sizeof(cksm)))) {
    return ret;
  }
  //  bpf_printk("before: %x", bpf_ntohs(cksm));
  cksm = bpf_htons(bpf_ntohs(cksm) + bpf_ntohs(new) - bpf_ntohs(old));
  if ((ret = bpf_skb_store_bytes(skb, l4_cksm_off, &cksm, sizeof(cksm), 0))) {
    return ret;
  }
  //  bpf_printk("after: %x", bpf_ntohs(cksm));
  return 0;
}

// rewrite_ip: rewrite the ip address in the packet
static __always_inline int rewrite_ip(struct __sk_buff *skb, __u8 ipversion,
                                      __u8 proto, __u8 ihl, __be32 old_ip[4],
                                      __be32 new_ip[4], bool is_dest,
                                      bool calc_l4_cksm)
                                      {
  // Nothing to do.
  if (equal16(old_ip, new_ip)) {
    return 0;
  }
  // bpf_printk("%pI6->%pI6", old_ip, new_ip);

  __u32 l4_cksm_off = l4_checksum_off(proto, ihl);
  int ret;
  // BPF_F_PSEUDO_HDR indicates the part we want to modify is part of the
  // pseudo header.
  __u32 l4flags = BPF_F_PSEUDO_HDR;
  if (proto == IPPROTO_UDP) {
    l4flags |= BPF_F_MARK_MANGLED_0;
  }

  if (ipversion == 4) {

    __be32 _old_ip = old_ip[3];
    __be32 _new_ip = new_ip[3];
    if (calc_l4_cksm) {

      int ret;
      // __sum16 test;
      // bpf_skb_load_bytes(skb, l4_cksm_off, &test, sizeof(test));
      // bpf_printk("rewrite ip before: %x, %pI4->%pI4", test, &_old_ip,
      // &_new_ip);
      if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, _old_ip, _new_ip,
                                     l4flags | sizeof(_new_ip)))) {
        bpf_printk("bpf_l4_csum_replace: %d", ret);
        return ret;
      }
    } else {
      // NIC checksum offload path. But problem remains. FIXME.
      if ((ret = bpf_update_offload_l4cksm_32(skb, l4_cksm_off, _old_ip,
                                              _new_ip))) {
        bpf_printk("bpf_update_offload_cksm_32: %d", ret);
        return ret;
      }
    }
    // bpf_skb_load_bytes(skb, l4_cksm_off, &test, sizeof(test));
    // bpf_printk("rewrite ip after: %x", test);

    if ((ret = bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, _old_ip, _new_ip,
                                   sizeof(_new_ip)))) {
      return ret;
    }
    // bpf_printk("%pI4 -> %pI4", &_old_ip, &_new_ip);

    ret = bpf_skb_store_bytes(skb, is_dest ? IPV4_DST_OFF : IPV4_SRC_OFF,
                              &_new_ip, sizeof(_new_ip), 0);
    if (ret) {
      bpf_printk("bpf_skb_store_bytes: %d", ret);
      return ret;
    }
  } else {

    if (calc_l4_cksm) {
      __s64 cksm =
          bpf_csum_diff(old_ip, IPV6_BYTE_LENGTH, new_ip, IPV6_BYTE_LENGTH, 0);
      if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, 0, cksm, l4flags))) {
        bpf_printk("bpf_l4_csum_replace: %d", ret);
        return ret;
      }
    }
    // bpf_printk("%pI6 -> %pI6", old_ip, new_ip);

    ret = bpf_skb_store_bytes(skb, is_dest ? IPV6_DST_OFF : IPV6_SRC_OFF,
                              new_ip, IPV6_BYTE_LENGTH, 0);
    if (ret) {
      bpf_printk("bpf_skb_store_bytes: %d", ret);
      return ret;
    }
  }

  return 0;
}

// rewrite_port: rewrite the port in the packet
static __always_inline int rewrite_port(struct __sk_buff *skb, __u8 proto,
                                        __u8 ihl, __be16 old_port,
                                        __be16 new_port, bool is_dest,
                                        bool calc_l4_cksm)
                                        {
  // Nothing to do.
  if (old_port == new_port) {
    return 0;
  }
  __u32 cksm_off = l4_checksum_off(proto, ihl), port_off = ETH_HLEN + ihl * 4;
  if (!cksm_off) {
    return -EINVAL;
  }
  __u32 l4flags = 0;
  switch (proto) {
  case IPPROTO_TCP:
    if (is_dest) {
      port_off += offsetof(struct tcphdr, dest);
    } else {
      port_off += offsetof(struct tcphdr, source);
    }
    break;

  case IPPROTO_UDP:
    if (is_dest) {
      port_off += offsetof(struct udphdr, dest);
    } else {
      port_off += offsetof(struct udphdr, source);
    }
    l4flags |= BPF_F_MARK_MANGLED_0;
    break;

  default:
    return -EINVAL;
  }

  // bpf_printk("%u -> %u", bpf_ntohs(old_port), bpf_ntohs(new_port));

  int ret;
  // __sum16 test;
  // if (!bpf_skb_load_bytes(skb, cksm_off, &test, sizeof(test))) {
  //   bpf_printk("rewrite port before: %x, %u->%u", test, bpf_ntohs(old_port),
  //              bpf_ntohs(new_port));
  // }
  if (calc_l4_cksm) {
    if ((ret = bpf_l4_csum_replace(skb, cksm_off, old_port, new_port,
                                   l4flags | sizeof(new_port)))) {
      bpf_printk("bpf_l4_csum_replace: %d", ret);
      return ret;
    }
  }
  // if (!bpf_skb_load_bytes(skb, cksm_off, &test, sizeof(test))) {
  //   bpf_printk("rewrite port aftetr: %x", test);
  // }

  if ((ret = bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port),
                                 0))) {
    return ret;
  }
  return 0;
}

// handle_ipv6_extensions: handle IPv6 extension headers
static __always_inline int handle_ipv6_extensions(const struct __sk_buff *skb,
                                                  __u32 offset, __u32 hdr,
                                                  struct tcphdr *tcph,
                                                  struct udphdr *udph,
                                                  __u8 *ihl, __u8 *l4proto)
                                                  {
  __u8 hdr_length = 0;
  __s32 *p_s32;
  __u8 nexthdr = 0;
  *ihl = sizeof(struct ipv6hdr) / 4;
  int ret;
  // We only process TCP and UDP traffic.

#pragma unroll
  for (int i = 0; i < IPV6_MAX_EXTENSIONS;
       i++, offset += hdr_length, hdr = nexthdr, *ihl += hdr_length / 4) {
    if (hdr_length % 4) {
      bpf_printk("IPv6 extension length is not multiples of 4");
      return 1;
    }
    // See component/control/control_plane.go.
    if (!(p_s32 = bpf_map_lookup_elem(&ipproto_hdrsize_map, &hdr))) {
      return 1;
    }

    switch (*p_s32) {
    case -1:
      if ((ret = bpf_skb_load_bytes(skb, offset + 1, &hdr_length,
                                    sizeof(hdr_length)))) {
        bpf_printk("not a valid IPv6 packet");
        return -EFAULT;
      }
    special_n1:
      if ((ret = bpf_skb_load_bytes(skb, offset, &nexthdr, sizeof(nexthdr)))) {
        bpf_printk("not a valid IPv6 packet");
        return -EFAULT;
      }
      break;
    case 4:
      hdr_length = 4;
      goto special_n1;
    case -2:
      *l4proto = hdr;
      if (hdr == IPPROTO_TCP) {
        __builtin_memset(tcph, 0, sizeof(struct udphdr));
        // Upper layer;
        if ((ret = bpf_skb_load_bytes(skb, offset, tcph,
                                      sizeof(struct tcphdr)))) {
          bpf_printk("not a valid IPv6 packet");
          return -EFAULT;
        }
      } else if (hdr == IPPROTO_UDP) {
        __builtin_memset(tcph, 0, sizeof(struct tcphdr));
        // Upper layer;
        if ((ret = bpf_skb_load_bytes(skb, offset, udph,
                                      sizeof(struct udphdr)))) {
          bpf_printk("not a valid IPv6 packet");
          return -EFAULT;
        }
      } else {
        // Unknown hdr.
        bpf_printk("Unexpected hdr.");
        return 1;
      }
      return 0;
    default:
      // Unknown hdr.
      return 1;
    }
  }
  bpf_printk("exceeds IPV6_MAX_EXTENSIONS limit");
  return 1;
}

static __always_inline int
parse_transport(const struct __sk_buff *skb, struct ethhdr *ethh,
                struct iphdr *iph, struct ipv6hdr *ipv6h, struct tcphdr *tcph,
                struct udphdr *udph, __u8 *ihl, __u8 *ipversion,
                __u8 *l4proto)
                {

  __u32 offset = 0;
  int ret;
  ret = bpf_skb_load_bytes(skb, offset, ethh, sizeof(struct ethhdr));
  if (ret) {
    bpf_printk("not ethernet packet");
    return 1;
  }
  // Skip ethhdr for next hdr.
  offset += sizeof(struct ethhdr);

  *ipversion = 0;
  *ihl = 0;
  *l4proto = 0;

  // bpf_printk("parse_transport: h_proto: %u ? %u %u", eth->h_proto,
  //            bpf_htons(ETH_P_IP), bpf_htons(ETH_P_IPV6));
  if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
    __builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
    *ipversion = 4;

    if ((ret = bpf_skb_load_bytes(skb, offset, iph, sizeof(struct iphdr)))) {
      return -EFAULT;
    }
    // Skip ipv4hdr and options for next hdr.
    offset += iph->ihl * 4;

    // We only process TCP and UDP traffic.
    *l4proto = iph->protocol;
    if (iph->protocol == IPPROTO_TCP) {
      __builtin_memset(udph, 0, sizeof(struct udphdr));
      if ((ret =
               bpf_skb_load_bytes(skb, offset, tcph, sizeof(struct tcphdr)))) {
        // Not a complete tcphdr.
        return -EFAULT;
      }
    } else if (iph->protocol == IPPROTO_UDP) {
      __builtin_memset(tcph, 0, sizeof(struct tcphdr));
      if ((ret =
               bpf_skb_load_bytes(skb, offset, udph, sizeof(struct udphdr)))) {
        // Not a complete tcphdr.
        return -EFAULT;
      }
    } else {
      // bpf_printk("IP but not TCP/UDP packet: protocol is %u", iph->protocol);
      return 1;
    }
    *ihl = iph->ihl;
    return 0;
  } else if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
    __builtin_memset(iph, 0, sizeof(struct iphdr));
    *ipversion = 6;

    if ((ret =
             bpf_skb_load_bytes(skb, offset, ipv6h, sizeof(struct ipv6hdr)))) {
      bpf_printk("not a valid IPv6 packet");
      return -EFAULT;
    }

    offset += sizeof(struct ipv6hdr);

    return handle_ipv6_extensions(skb, offset, ipv6h->nexthdr, tcph, udph, ihl,
                                  l4proto);
  } else {
    return 1;
  }
}

static __always_inline int adjust_udp_len(struct __sk_buff *skb, __u16 oldlen,
                                          __u32 ihl, __u16 len_diff,
                                          bool calc_l4_cksm)
                                          {
  if (unlikely(!len_diff)) {
    return 0;
  }

  // Boundary check.
  if (len_diff > 0) {
    if (unlikely(bpf_ntohs(oldlen) + len_diff < len_diff)) { // overflow
      bpf_printk("udp length overflow");
      return -EINVAL;
    }
  } else {
    if (unlikely((__s32)bpf_ntohs(oldlen) + len_diff < 0)) { // not enough
      bpf_printk("udp length not enough");
      return -EINVAL;
    }
  }
  __be16 newlen = bpf_htons(bpf_ntohs(oldlen) + len_diff);

  // Calculate checksum and store the new value.
  int ret;
  __u32 udp_csum_off = l4_checksum_off(IPPROTO_UDP, ihl);
  if (calc_l4_cksm) {
    // replace twice because len exists both pseudo hdr and hdr.
    if ((ret = bpf_l4_csum_replace(
             skb, udp_csum_off, oldlen, newlen,
             sizeof(oldlen) | BPF_F_PSEUDO_HDR | // udp len is in the pseudo hdr
                 BPF_F_MARK_MANGLED_0))) {
      bpf_printk("bpf_l4_csum_replace newudplen: %d", ret);
      return ret;
    }
    if ((ret = bpf_l4_csum_replace(skb, udp_csum_off, oldlen, newlen,
                                   sizeof(oldlen) | BPF_F_MARK_MANGLED_0))) {
      bpf_printk("bpf_l4_csum_replace newudplen: %d", ret);
      return ret;
    }
  } else {
    // NIC checksum offload path. But problem remains. FIXME.
    if ((ret =
             bpf_update_offload_l4cksm_16(skb, udp_csum_off, oldlen, newlen))) {
      bpf_printk("bpf_update_offload_cksm: %d", ret);
      return ret;
    }
  }
  if ((ret = bpf_skb_store_bytes(
           skb, (__u32)ETH_HLEN + ihl * 4 + offsetof(struct udphdr, len),
           &newlen, sizeof(oldlen), 0))) {
    bpf_printk("bpf_skb_store_bytes newudplen: %d", ret);
    return ret;
  }
  return 0;
}

static __always_inline int adjust_ipv4_len(struct __sk_buff *skb, __u16 oldlen,
                                           __u16 len_diff) {
  if (unlikely(!len_diff)) {
    return 0;
  }

  // Boundary check.
  if (len_diff > 0) {
    if (unlikely(bpf_ntohs(oldlen) + len_diff < len_diff)) { // overflow
      bpf_printk("ip length overflow");
      return -EINVAL;
    }
  } else {
    if (unlikely((__s32)bpf_ntohs(oldlen) + len_diff < 0)) { // not enough
      bpf_printk("ip length not enough");
      return -EINVAL;
    }
  }
  __be16 newlen = bpf_htons(bpf_ntohs(oldlen) + len_diff);

  // Calculate checksum and store the new value.
  int ret;
  if ((ret = bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, oldlen, newlen,
                                 sizeof(oldlen)))) {
    bpf_printk("bpf_l3_csum_replace newudplen: %d", ret);
    return ret;
  }
  if ((ret = bpf_skb_store_bytes(
           skb, (__u32)ETH_HLEN + offsetof(struct iphdr, tot_len), &newlen,
           sizeof(oldlen), 0))) {
    bpf_printk("bpf_skb_store_bytes newiplen: %d", ret);
    return ret;
  }
  return 0;
}

static __always_inline int encap_after_udp_hdr(struct __sk_buff *skb,
                                               __u8 ipversion, __u8 ihl,
                                               __be16 iphdr_tot_len,
                                               void *newhdr, __u32 newhdrlen,
                                               bool calc_l4_cksm)
                                               {
  if (unlikely(newhdrlen % 4 != 0)) {
    bpf_printk("encap_after_udp_hdr: unexpected newhdrlen value %u :must "
               "be a multiple of 4",
               newhdrlen);
    return -EINVAL;
  }

  int ret = 0;
  long ip_off = ETH_HLEN;
  // Calculate offsets using add instead of subtract to avoid verifier problems.
  long ipp_len = ihl * 4;
  long udp_payload_off = ip_off + ipp_len + sizeof(struct udphdr);

  // Backup for further use.
  struct udphdr reserved_udphdr;
  if ((ret = bpf_skb_load_bytes(skb, ip_off + ipp_len, &reserved_udphdr,
                                sizeof(reserved_udphdr)))) {
    bpf_printk("bpf_skb_load_bytes: %d", ret);
    return ret;
  }
  // Add room for new udp payload header.
  if ((ret = bpf_skb_adjust_room(skb, newhdrlen, BPF_ADJ_ROOM_NET,
                                 calc_l4_cksm ? BPF_F_ADJ_ROOM_NO_CSUM_RESET
                                              : 0))) {
    bpf_printk("UDP ADJUST ROOM(encap): %d", ret);
    return ret;
  }
  // Move the new room to the front of the UDP payload.
  if ((ret = bpf_skb_store_bytes(skb, ip_off + ipp_len, &reserved_udphdr,
                                 sizeof(reserved_udphdr), 0))) {
    bpf_printk("bpf_skb_store_bytes reserved_udphdr: %d", ret);
    return ret;
  }

  // Rewrite ip len.
  if (ipversion == 4) {
    if ((ret = adjust_ipv4_len(skb, iphdr_tot_len, newhdrlen))) {
      bpf_printk("adjust_ip_len: %d", ret);
      return ret;
    }
  }

  // Rewrite udp len.
  if ((ret = adjust_udp_len(skb, reserved_udphdr.len, ihl, newhdrlen,
                            calc_l4_cksm))) {
    bpf_printk("adjust_udp_len: %d", ret);
    return ret;
  }

  // Rewrite udp payload.
  if (calc_l4_cksm) {
    __u32 l4_cksm_off = l4_checksum_off(IPPROTO_UDP, ihl);
    __s64 cksm = bpf_csum_diff(NULL, 0, newhdr, newhdrlen, 0);
    if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, 0, cksm,
                                   BPF_F_MARK_MANGLED_0))) {
      bpf_printk("bpf_l4_csum_replace 2: %d", ret);
      return ret;
    }
  }
  if ((ret = bpf_skb_store_bytes(skb, udp_payload_off, newhdr, newhdrlen, 0))) {
    bpf_printk("bpf_skb_store_bytes 2: %d", ret);
    return ret;
  }
  return 0;
}

static __always_inline int decap_after_udp_hdr(struct __sk_buff *skb,
                                               __u8 ipversion, __u8 ihl,
                                               __be16 ipv4hdr_tot_len, void *to,
                                               __u32 decap_hdrlen,
                                               bool calc_l4_cksm)
                                               {
  if (unlikely(decap_hdrlen % 4 != 0)) {
    bpf_printk("encap_after_udp_hdr: unexpected decap_hdrlen value %u :must "
               "be a multiple of 4",
               decap_hdrlen);
    return -EINVAL;
  }
  int ret = 0;
  long ip_off = ETH_HLEN;
  // Calculate offsets using add instead of subtract to avoid verifier problems.
  long ipp_len = ihl * 4;

  // Must check lower boundary for packet offset (and set the type of the
  // variables to signed long).
  if (skb->data + ip_off + ipp_len > skb->data_end) {
    return -EINVAL;
  }

  // Backup for further use.
  struct udphdr reserved_udphdr;
  if ((ret = bpf_skb_load_bytes(skb, ip_off + ipp_len, &reserved_udphdr,
                                sizeof(struct udphdr)))) {
    bpf_printk("bpf_skb_load_bytes: %d", ret);
    return ret;
  }

  // Load the hdr to decap.
  if ((ret = bpf_skb_load_bytes(skb, ip_off + ipp_len + sizeof(struct udphdr),
                                to, decap_hdrlen))) {
    bpf_printk("bpf_skb_load_bytes decap_hdr: %d", ret);
    return ret;
  }

  // Move the udphdr to the front of the real UDP payload.
  if ((ret =
           bpf_skb_store_bytes(skb, ip_off + ipp_len + decap_hdrlen,
                               &reserved_udphdr, sizeof(reserved_udphdr), 0))) {
    bpf_printk("bpf_skb_store_bytes reserved_udphdr: %d", ret);
    return ret;
  }

  // Adjust room to decap the header.
  if ((ret = bpf_skb_adjust_room(skb, -decap_hdrlen, BPF_ADJ_ROOM_NET,
                                 calc_l4_cksm ? BPF_F_ADJ_ROOM_NO_CSUM_RESET
                                              : 0))) {
    bpf_printk("UDP ADJUST ROOM(decap): %d", ret);
    return ret;
  }

  // Rewrite ip len.
  if (ipversion == 4) {
    if ((ret = adjust_ipv4_len(skb, ipv4hdr_tot_len, -decap_hdrlen))) {
      bpf_printk("adjust_ip_len: %d", ret);
      return ret;
    }
  }

  // Rewrite udp len.
  if ((ret = adjust_udp_len(skb, reserved_udphdr.len, ihl, -decap_hdrlen,
                            calc_l4_cksm))) {
    bpf_printk("adjust_udp_len: %d", ret);
    return ret;
  }

  // Rewrite udp checksum.
  if (calc_l4_cksm) {
    __u32 udp_csum_off = l4_checksum_off(IPPROTO_UDP, ihl);
    __s64 cksm = bpf_csum_diff(to, decap_hdrlen, 0, 0, 0);
    if ((ret = bpf_l4_csum_replace(skb, udp_csum_off, 0, cksm,
                                   BPF_F_MARK_MANGLED_0))) {
      bpf_printk("bpf_l4_csum_replace 2: %d", ret);
      return ret;
    }
  }
  return 0;
}

// Do not use __always_inline here because this function is too heavy.
// routing is called by the main function.
static int __attribute__((noinline))
routing(const __u32 flag[6], const void *l4hdr, const __be32 saddr[4],
        const __be32 _daddr[4], const __be32 mac[4])
        {
#define _l4proto_type flag[0]
#define _ipversion_type flag[1]
#define _pname &flag[2]
#define _is_wan flag[2]

  int ret;
  struct lpm_key lpm_key_instance, *lpm_key;
  __u32 key = MatchType_L4Proto;
  __u16 h_dport;
  __u16 h_sport;
  __u32 daddr[4];

  /// TODO: BPF_MAP_UPDATE_BATCH ?
  if (unlikely((ret = bpf_map_update_elem(&l4proto_ipversion_map, &key,
                                          &_l4proto_type, BPF_ANY)))) {
    return ret;
  };
  key = MatchType_IpVersion;
  if (unlikely((ret = bpf_map_update_elem(&l4proto_ipversion_map, &key,
                                          &_ipversion_type, BPF_ANY)))) {
    return ret;
  };

  // Variables for further use.
  if (_l4proto_type == L4ProtoType_TCP) {
    h_dport = bpf_ntohs(((struct tcphdr *)l4hdr)->dest);
    h_sport = bpf_ntohs(((struct tcphdr *)l4hdr)->source);
  } else {
    h_dport = bpf_ntohs(((struct udphdr *)l4hdr)->dest);
    h_sport = bpf_ntohs(((struct udphdr *)l4hdr)->source);
  }

  key = MatchType_SourcePort;
  if (unlikely(
          (ret = bpf_map_update_elem(&h_port_map, &key, &h_sport, BPF_ANY)))) {
    return ret;
  };
  key = MatchType_Port;
  if (unlikely(
          (ret = bpf_map_update_elem(&h_port_map, &key, &h_dport, BPF_ANY)))) {
    return ret;
  };

  // Modify DNS upstream for routing.
  if (h_dport == 53 && _l4proto_type == L4ProtoType_UDP) {
    struct ip_port *upstream =
        bpf_map_lookup_elem(&dns_upstream_map, &zero_key);
    if (upstream && upstream->port != 0) {
      h_dport = bpf_ntohs(upstream->port);
      __builtin_memcpy(daddr, upstream->ip, IPV6_BYTE_LENGTH);
    } else {
      __builtin_memcpy(daddr, _daddr, IPV6_BYTE_LENGTH);
    }
  } else {
    __builtin_memcpy(daddr, _daddr, IPV6_BYTE_LENGTH);
  }
  lpm_key_instance.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
  __builtin_memcpy(lpm_key_instance.data, daddr, IPV6_BYTE_LENGTH);
  key = MatchType_IpSet;
  if (unlikely((ret = bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_instance,
                                          BPF_ANY)))) {
    return ret;
  };
  __builtin_memcpy(lpm_key_instance.data, saddr, IPV6_BYTE_LENGTH);
  key = MatchType_SourceIpSet;
  if (unlikely((ret = bpf_map_update_elem(&lpm_key_map, &key, &lpm_key_instance,
                                          BPF_ANY)))) {
    return ret;
  };
  if (!_is_wan) {
    __builtin_memcpy(lpm_key_instance.data, mac, IPV6_BYTE_LENGTH);
    key = MatchType_Mac;
    if (unlikely((ret = bpf_map_update_elem(&lpm_key_map, &key,
                                            &lpm_key_instance, BPF_ANY)))) {
      return ret;
    };
  }

  struct map_lpm_type *lpm;
  struct match_set *match_set;
  // Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
  // proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
  // set is like: suffix:baidu.com
  bool bad_rule = false;
  bool good_subrule = false;
  struct domain_routing *domain_routing;
  __u32 *p_u32;
  __u16 *p_u16;

#pragma unroll
  for (__u32 i = 0; i < MAX_MATCH_SET_LEN; i++) {
    __u32 k = i; // Clone to pass code checker.
    match_set = bpf_map_lookup_elem(&routing_map, &k);
    if (unlikely(!match_set)) {
      return -EFAULT;
    }
    if (bad_rule || good_subrule) {
#ifdef __DEBUG_ROUTING
      key = match_set->type;
      bpf_printk("key(match_set->type): %llu", key);
      bpf_printk("Skip to judge. bad_rule: %d, good_subrule: %d", bad_rule,
                 good_subrule);
#endif
      goto before_next_loop;
    }
    key = match_set->type;
#ifdef __DEBUG_ROUTING
    bpf_printk("key(match_set->type): %llu", key);
#endif
    if ((lpm_key = bpf_map_lookup_elem(&lpm_key_map, &key))) {
#ifdef __DEBUG_ROUTING
      bpf_printk(
          "CHECK: lpm_key_map, match_set->type: %u, not: %d, outbound: %u",
          match_set->type, match_set->not, match_set->outbound);
      bpf_printk("\tip: %pI6", lpm_key->data);
#endif
      lpm = bpf_map_lookup_elem(&lpm_array_map, &match_set->index);
      if (unlikely(!lpm)) {
        return -EFAULT;
      }
      if (bpf_map_lookup_elem(lpm, lpm_key)) {
        // match_set hits.
        good_subrule = true;
      }
    } else if ((p_u16 = bpf_map_lookup_elem(&h_port_map, &key))) {
#ifdef __DEBUG_ROUTING
      bpf_printk(
          "CHECK: h_port_map, match_set->type: %u, not: %d, outbound: %u",
          match_set->type, match_set->not, match_set->outbound);
      bpf_printk("\tport: %u, range: [%u, %u]", *p_u16,
                 match_set->port_range.port_start,
                 match_set->port_range.port_end);
#endif
      if (*p_u16 >= match_set->port_range.port_start &&
          *p_u16 <= match_set->port_range.port_end) {
        good_subrule = true;
      }
    } else if ((p_u32 = bpf_map_lookup_elem(&l4proto_ipversion_map, &key))) {
#ifdef __DEBUG_ROUTING
      bpf_printk("CHECK: l4proto_ipversion_map, match_set->type: %u, not: %d, "
                 "outbound: %u",
                 match_set->type, match_set->not, match_set->outbound);
#endif
      if (*p_u32 & *(__u32 *)&match_set->__value) {
        good_subrule = true;
      }
    } else if (match_set->type == MatchType_DomainSet) {
#ifdef __DEBUG_ROUTING
      bpf_printk("CHECK: domain, match_set->type: %u, not: %d, "
                 "outbound: %u",
                 match_set->type, match_set->not, match_set->outbound);
#endif

      // Get domain routing bitmap.
      domain_routing = bpf_map_lookup_elem(&domain_routing_map, daddr);
      if (!domain_routing) {
        // No domain corresponding to IP.
        goto before_next_loop;
      }

      // We use key instead of k to pass checker.
      if ((domain_routing->bitmap[i / 32] >> (i % 32)) & 1) {
        good_subrule = true;
      }
    } else if (match_set->type == MatchType_ProcessName) {
      if (_is_wan && equal16(match_set->pname, _pname)) {
        good_subrule = true;
      }
    } else if (match_set->type == MatchType_Final) {
#ifdef __DEBUG_ROUTING
      bpf_printk("CHECK: hit final");
#endif
      good_subrule = true;
    } else {
#ifdef __DEBUG_ROUTING
      bpf_printk("CHECK: <unknown>, match_set->type: %u, not: %d, "
                 "outbound: %u",
                 match_set->type, match_set->not, match_set->outbound);
#endif
      return -EINVAL;
    }

  before_next_loop:
#ifdef __DEBUG_ROUTING
    bpf_printk("good_subrule: %d, bad_rule: %d", good_subrule, bad_rule);
#endif
    if (match_set->outbound != OUTBOUND_LOGICAL_OR) {
      // This match_set reaches the end of subrule.
      // We are now at end of rule, or next match_set belongs to another
      // subrule.

      if (good_subrule == match_set->not ) {
        // This subrule does not hit.
        bad_rule = true;
      }

      // Reset good_subrule.
      good_subrule = false;
    }
#ifdef __DEBUG_ROUTING
    bpf_printk("_bad_rule: %d", bad_rule);
#endif
    if ((match_set->outbound & OUTBOUND_LOGICAL_MASK) !=
        OUTBOUND_LOGICAL_MASK) {
      // Tail of a rule (line).
      // Decide whether to hit.
      if (!bad_rule) {
#ifdef __DEBUG_ROUTING
        bpf_printk("MATCHED: match_set->type: %u, match_set->not: %d",
                   match_set->type, match_set->not );
#endif
        if (match_set->outbound == OUTBOUND_DIRECT && h_dport == 53 &&
            _l4proto_type == L4ProtoType_UDP) {
          // DNS packet should go through control plane.
          return OUTBOUND_CONTROL_PLANE_DIRECT;
        }
        return match_set->outbound;
      }
      bad_rule = false;
    }
  }
  bpf_printk("No match_set hits. Did coder forget to sync "
             "common/consts/ebpf.go with enum MatchType?");
  return -EPERM;
#undef _l4proto_type
#undef _ipversion_type
#undef _pname
#undef _is_wan
}

// Cookie will change after the first packet, so we just use it for
// handshake.
static __always_inline bool pid_is_control_plane(struct __sk_buff *skb,
                                                 struct pid_pname **p) {

  struct pid_pname *pid_pname;
  __u64 cookie = bpf_get_socket_cookie(skb);
  pid_pname = bpf_map_lookup_elem(&cookie_pid_map, &cookie);
  if (pid_pname) {
    if (p) {
      // Assign.
      *p = pid_pname;
    }
    // Get tproxy pid and compare if they are equal.
    __u32 *pid_tproxy;
    if (!(pid_tproxy =
              bpf_map_lookup_elem(&param_map, &control_plane_pid_key))) {
      bpf_printk("control_plane_pid is not set.");
      return false;
    }
    return pid_pname->pid == *pid_tproxy;
  } else {
    if (p) {
      *p = NULL;
    }
    if ((skb->mark & 0x100) == 0x100) {
      bpf_printk("No pid_pname found. But it should not happen");
      /*
      if (l4proto == IPPROTO_TCP) {
        if (tcph.syn && !tcph.ack) {
          bpf_printk("No pid_pname found. But it should not happen: local:%u "
                     "(%u)[%llu]",
                     bpf_ntohs(sport), l4proto, cookie);
        } else {
          bpf_printk("No pid_pname found. But it should not happen: (Old "
                     "Connection): local:%u "
                     "(%u)[%llu]",
                     bpf_ntohs(sport), l4proto, cookie);
        }
      } else {
        bpf_printk("No pid_pname found. But it should not happen: local:%u "
                   "(%u)[%llu]",
                   bpf_ntohs(sport), l4proto, cookie);
      }
      */
      return true;
    }
    return false;
  }
}

static __always_inline bool wan_disable_checksum(const __u32 ifindex,
                                                 const __u8 ipversion) {

  struct if_params *ifparams =
      bpf_map_lookup_elem(&ifindex_params_map, &ifindex);
  if (unlikely(!ifparams)) {
    return -1;
  }
  bool tx_offloaded = (ipversion == 4 && ifparams->tx_l4_cksm_ip4_offload) ||
                      (ipversion == 6 && ifparams->tx_l4_cksm_ip6_offload);
  // If tx offloaded, we get bad checksum of packets because we redirect packet
  // before the NIC processing. So we have no choice but disable l4 checksum.

  bool disable_l4_checksum = tx_offloaded;

  return disable_l4_checksum;
}


static int __always_inline update_map_elem_by_cookie(const __u64 cookie) {
  if (unlikely(!cookie)) {
    bpf_printk("zero cookie");
    return -EINVAL;
  }
  int ret;

  // Build value.
  struct pid_pname val;
  __builtin_memset(&val, 0, sizeof(struct pid_pname));
  char buf[MAX_ARG_SCANNER_BUFFER_SIZE] = {0};
  struct task_struct *current = (void *)bpf_get_current_task();
  unsigned long arg_start = BPF_PROBE_READ_KERNEL(current, mm, arg_start);
  unsigned long arg_end = BPF_PROBE_READ_KERNEL(current, mm, arg_end);
  unsigned long arg_len = arg_end - arg_start;
  if (arg_len > MAX_ARG_LEN_TO_PROBE) {
    arg_len = MAX_ARG_LEN_TO_PROBE;
  }

  /**
  For string like: /usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth1
  We extract "sddm-helper" from it.
  */
  unsigned long loc, j;
  unsigned long last_slash = -1;
#pragma unroll
  for (loc = 0, j = 0; j < MAX_ARG_LEN_TO_PROBE;
       ++j, loc = ((loc + 1) & (MAX_ARG_SCANNER_BUFFER_SIZE - 1))) {
    // volatile unsigned long k = j; // Cheat to unroll.
    if (unlikely(arg_start + j >= arg_end)) {
      break;
    }
    if (unlikely(loc == 0)) {
      /// WANRING: Do NOT use bpf_core_read_user_str, it will bring terminator
      /// 0.
      // __builtin_memset(&buf, 0, MAX_ARG_SCANNER_BUFFER_SIZE);
      unsigned long to_read = arg_end - (arg_start + j);
      if (to_read >= MAX_ARG_SCANNER_BUFFER_SIZE) {
        to_read = MAX_ARG_SCANNER_BUFFER_SIZE;
      } else {
        buf[to_read] = 0;
      }
      // No need to CO-RE.
      if ((ret = bpf_probe_read_user(&buf, to_read,
                                     (const void *)(arg_start + j)))) {
        bpf_printk("failed to read process name: %d", ret);
        return ret;
      }
    }
    if (unlikely(buf[loc] == '/')) {
      last_slash = j;
    } else if (unlikely(buf[loc] == ' ' || buf[loc] == 0)) {
      break;
    }
  }
  ++last_slash;
  unsigned long length_cpy = j - last_slash;
  if (length_cpy > TASK_COMM_LEN) {
    length_cpy = TASK_COMM_LEN;
  }
  if ((ret = bpf_probe_read_user(&val.pname, length_cpy,
                                 (const void *)(arg_start + last_slash)))) {
    bpf_printk("failed to read process name: %d", ret);
    return ret;
  }
  bpf_probe_read_kernel(&val.pid, sizeof(val.pid), &current->tgid);
  // bpf_printk("a start_end: %lu %lu", arg_start, arg_end);
  // bpf_printk("b start_end: %lu %lu", arg_start + last_slash, arg_start + j);

  // Update map.
  if (unlikely(ret = bpf_map_update_elem(&cookie_pid_map, &cookie, &val,
                                         BPF_NOEXIST))) {
    // bpf_printk("setup_mapping_from_sk: failed update map: %d", ret);
    return ret;
  }

  bpf_printk("setup_mapping: %llu -> %s (%d)", cookie, val.pname, val.pid);
  return 0;
}

#endif