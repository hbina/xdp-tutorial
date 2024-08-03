/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <locale.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#define __USE_MISC 1

#include <arpa/inet.h>
// #include <net/if_arp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
// #include <linux/icmp.h>
// #include <linux/icmpv6.h>
// #include <linux/if.h>
// #include <linux/if_ether.h>
// #include <linux/if_link.h>
// #include <linux/ip.h>
// #include <linux/ipv6.h>
// #include <net/if.h>

#include "../common/common_libbpf.h"
#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX

static struct xdp_program *prog;
int xsk_map_fd;
bool custom_xsk = false;
struct config cfg = {
    .ifindex = -1,
};

struct xsk_umem_info {
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem *umem;
  void *buffer;
};
struct xsk_socket_info {
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_umem_info *umem;
  struct xsk_socket *xsk;

  uint64_t umem_frame_addr[NUM_FRAMES];
  uint32_t umem_frame_free;

  uint32_t outstanding_tx;
};

// const char *SRC_MC = "\xCA\x88\x4F\xAE\xD1\x61";Q
const char *DST_MAC = "\xCA\x88\x4F\xAE\xD1\x61";
// const char *SRC_MC = "\x56\x0C\xF9\xFF\x19\xE8";
// const char *DST_MAC = "\x56\x0C\xF9\xFF\x19\xE8";
const char *SRC_MC = "\xFA\x0E\x55\x24\x54\xC2";
// const char *DST_MAC = "\xFA\x0E\x55\x24\x54\xC2";
// fa:0e:55:24:54:c2

static void print_ethernet_header(const struct ethhdr *eth) {
  printf("Ethernet Header\n");
  printf("\t|-Destination Address : ");
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    printf("%02X%c", eth->h_dest[i], (i == ETHER_ADDR_LEN - 1) ? ' ' : ':');
  }
  printf("\n");
  printf("\t|-Source Address      : ");
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    printf("%02X%c", eth->h_source[i], (i == ETHER_ADDR_LEN - 1) ? ' ' : ':');
  }
  printf("\n");
  printf("\t|-EtherType           : 0x%04X\n", ntohs(eth->h_proto));
}

static void print_ipv4_header(const struct iphdr *ip) {
  char src_addr[INET_ADDRSTRLEN];
  char dst_addr[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &(ip->saddr), src_addr, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip->daddr), dst_addr, INET_ADDRSTRLEN);

  printf("IPv4 Header\n");
  printf("\t|-Version              : %d\n", ip->version);
  printf("\t|-Header Length        : %d DWORDS or %d Bytes\n", ip->ihl,
         ip->ihl * 4);
  printf("\t|-Type of Service      : %d\n", ip->tos);
  printf("\t|-Total Length         : %d Bytes\n", ntohs(ip->tot_len));
  printf("\t|-Identification       : %d\n", ntohs(ip->id));
  printf("\t|-Fragment Offset      : %d\n", ntohs(ip->frag_off));
  printf("\t|-Time to Live         : %d\n", ip->ttl);
  printf("\t|-Protocol             : %d\n", ip->protocol);
  printf("\t|-Header Checksum      : %d\n", ntohs(ip->check));
  printf("\t|-Source IP            : %s\n", src_addr);
  printf("\t|-Destination IP       : %s\n", dst_addr);
}

static void print_ipv6_header(const struct ip6_hdr *ip6) {
  char src_addr[INET6_ADDRSTRLEN];
  char dst_addr[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET6, &(ip6->ip6_src), src_addr, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_addr, INET6_ADDRSTRLEN);

  // uint32_t version = (ntohl(ip6->version_traffic_class_flow_label) >> 28) &
  // 0xF; uint32_t traffic_class =
  //     (ntohl(ip6->version_traffic_class_flow_label) >> 20) & 0xFF;
  // uint32_t flow_label = ntohl(ip6->version_traffic_class_flow_label) &
  // 0xFFFFF;

  printf("IPv6 Header\n");
  // printf("   |-Version              : %u\n", version);
  // printf("   |-Traffic Class        : %u\n", traffic_class);
  // printf("   |-Flow Label           : %u\n", flow_label);
  // printf("   |-Payload Length       : %u Bytes\n",
  // ntohs(ip6->payload_length)); printf("   |-Next Header          : %u\n",
  // ip6->next_header); printf("   |-Hop Limit            : %u\n",
  // ip6->hop_limit);
  printf("   |-Source Address       : %s\n", src_addr);
  printf("   |-Destination Address  : %s\n", dst_addr);
}

static void print_tcp_header(const struct tcphdr *tcp) {
  printf("TCP Header\n");
  printf("\t|-Source Port          : %d\n", ntohs(tcp->source));
  printf("\t|-Destination Port     : %d\n", ntohs(tcp->dest));
  printf("\t|-Sequence Number      : %u\n", ntohl(tcp->seq));
  printf("\t|-Acknowledge Number   : %u\n", ntohl(tcp->ack_seq));
  printf("\t|-Header Length        : %d DWORDS or %d Bytes\n", tcp->doff,
         tcp->doff * 4);
  printf("\t|-Flags                : %d\n", tcp->th_flags);
  printf("\t|-Window               : %d\n", ntohs(tcp->window));
  printf("\t|-Checksum             : %d\n", ntohs(tcp->check));
  printf("\t|-Urgent Pointer       : %d\n", tcp->urg_ptr);
}

static void print_arp_header(const struct ether_arp *arp) {
  char sender_ip[INET_ADDRSTRLEN];
  char target_ip[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &(arp->arp_spa), sender_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(arp->arp_tpa), target_ip, INET_ADDRSTRLEN);

  printf("ARP Header\n");
  printf("\t|-Hardware Type        : %u\n", ntohs(arp->ea_hdr.ar_hrd));
  printf("\t|-Protocol Type        : 0x%04X\n", ntohs(arp->ea_hdr.ar_pro));
  printf("\t|-Hardware Address Length: %u\n", arp->ea_hdr.ar_hln);
  printf("\t|-Protocol Address Length: %u\n", arp->ea_hdr.ar_pln);
  printf("\t|-Operation            : %u\n", ntohs(arp->ea_hdr.ar_op));
  printf("\t|-Sender MAC Address   : ");
  for (int i = 0; i < ETH_ALEN; i++)
    printf("%02X%c", arp->arp_sha[i], (i == ETH_ALEN - 1) ? ' ' : ':');
  printf("\n");
  printf("\t|-Sender IP Address    : %s\n", sender_ip);
  printf("\t|-Target MAC Address   : ");
  for (int i = 0; i < ETH_ALEN; i++)
    printf("%02X%c", arp->arp_tha[i], (i == ETH_ALEN - 1) ? ' ' : ':');
  printf("\n");
  printf("\t|-Target IP Address    : %s\n", target_ip);
}

static void print_icmp_header(const struct icmphdr *icmp) {
  printf("ICMP Header\n");
  printf("\t|-Type                 : %d\n", icmp->type);
  printf("\t|-Code                 : %d\n", icmp->code);
  printf("\t|-Checksum             : %d\n", ntohs(icmp->checksum));
  printf("\t|-Identification       : %d\n", ntohs(icmp->un.echo.id));
  printf("\t|-Sequence Number      : %d\n", ntohs(icmp->un.echo.sequence));
}

void print_icmpv6_header(const struct icmp6_hdr *icmpv6) {
  printf("ICMPv6 Header\n");
  printf("\t|-Type                 : %d\n", icmpv6->icmp6_type);
  printf("\t|-Code                 : %d\n", icmpv6->icmp6_code);
  printf("\t|-Checksum             : %d\n", ntohs(icmpv6->icmp6_cksum));
  printf("\t|-Reserved             : %u\n",
         ntohl(icmpv6->icmp6_dataun.icmp6_un_data32[0]));
}

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r) {
  r->cached_cons = *r->consumer + r->size;
  return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

    {{"help", no_argument, NULL, 'h'}, "Show help", false},

    {{"dev", required_argument, NULL, 'd'},
     "Operate on device <ifname>",
     "<ifname>",
     true},

    {{"skb-mode", no_argument, NULL, 'S'},
     "Install XDP program in SKB (AKA generic) mode"},

    {{"native-mode", no_argument, NULL, 'N'},
     "Install XDP program in native mode"},

    {{"auto-mode", no_argument, NULL, 'A'}, "Auto-detect SKB or native mode"},

    {{"force", no_argument, NULL, 'F'},
     "Force install, replacing existing program on interface"},

    {{"copy", no_argument, NULL, 'c'}, "Force copy mode"},

    {{"zero-copy", no_argument, NULL, 'z'}, "Force zero-copy mode"},

    {{"queue", required_argument, NULL, 'Q'},
     "Configure interface receive queue for AF_XDP, default=0"},

    {{"poll-mode", no_argument, NULL, 'p'},
     "Use the poll() API waiting for packets to arrive"},

    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},

    {{"filename", required_argument, NULL, 1},
     "Load program from <file>",
     "<file>"},

    {{"progname", required_argument, NULL, 2},
     "Load program from function <name> in the ELF file",
     "<name>"},

    {{0, 0, NULL, 0}, NULL, false}};

static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size) {
  struct xsk_umem_info *umem;
  int ret;

  umem = calloc(1, sizeof(*umem));
  if (!umem)
    return NULL;

  ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
  if (ret) {
    errno = -ret;
    return NULL;
  }

  umem->buffer = buffer;
  return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
  uint64_t frame;
  if (xsk->umem_frame_free == 0)
    return INVALID_UMEM_FRAME;

  frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
  xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame) {
  assert(xsk->umem_frame_free < NUM_FRAMES);

  xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk) {
  return xsk->umem_frame_free;
}

static struct xsk_socket_info *
xsk_configure_socket(struct config *cfg, struct xsk_umem_info *umem) {
  struct xsk_socket_config xsk_cfg;
  struct xsk_socket_info *xsk_info;
  uint32_t idx;
  int i;
  int ret;
  uint32_t prog_id;

  xsk_info = calloc(1, sizeof(*xsk_info));
  if (!xsk_info)
    return NULL;

  xsk_info->umem = umem;
  xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  xsk_cfg.xdp_flags = cfg->xdp_flags;
  xsk_cfg.bind_flags = cfg->xsk_bind_flags;
  xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0;
  ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname, cfg->xsk_if_queue,
                           umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
  if (ret)
    goto error_exit;

  if (custom_xsk) {
    ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
    if (ret)
      goto error_exit;
  } else {
    /* Getting the program ID must be after the xdp_socket__create() call */
    if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
      goto error_exit;
  }

  /* Initialize umem frame allocation */
  for (i = 0; i < NUM_FRAMES; i++)
    xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

  xsk_info->umem_frame_free = NUM_FRAMES;

  /* Stuff the receive path with buffers, we assume we have enough */
  ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                               XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);

  if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    goto error_exit;

  for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
    *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
        xsk_alloc_umem_frame(xsk_info);

  xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

  return xsk_info;

error_exit:
  errno = -ret;
  return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk) {
  unsigned int completed;
  uint32_t idx_cq;

  if (!xsk->outstanding_tx) {
    return;
  }

  sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

  /* Collect/free completed TX buffers */
  completed = xsk_ring_cons__peek(&xsk->umem->cq,
                                  XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

  if (completed > 0) {
    for (int i = 0; i < completed; i++) {
      xsk_free_umem_frame(xsk,
                          *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++));
    }

    xsk_ring_cons__release(&xsk->umem->cq, completed);
    xsk->outstanding_tx -=
        completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
  }
}

static inline uint16_t calc_cksum(uint8_t *addr, uint32_t count) {
  uint32_t sum = 0;

  int iter = 0;
  while (count > 1) {
    uint16_t *addr16 = (uint16_t *)addr;
    sum = sum + *(addr16 + iter);
    count = count - 2;
    iter = iter + 1;
  }

  if (count > 0) {
    sum = sum + *(addr + (iter * 2));
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  uint16_t answer = ~sum & 0xFFFF;

  return answer;
}

static bool process_icmp_v6(struct xsk_socket_info *xsk, uint64_t addr,
                            uint32_t len) {
  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  if (len < (sizeof(struct ethhdr) + sizeof(struct ip6_hdr) +
             sizeof(struct icmp6_hdr))) {
    return false;
  }

  struct ethhdr *eth_hdr = (struct ethhdr *)pkt;
  struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)(eth_hdr + 1);
  struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(ipv6_hdr + 1);

  if (ntohs(eth_hdr->h_proto) != ETH_P_IPV6 ||
      ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6 ||
      icmp6_hdr->icmp6_type != ICMP6_ECHO_REQUEST) {
    return false;
  }

  printf("ICMP6 <<<<<<<<\n");
  print_ethernet_header(eth_hdr);
  print_ipv6_header(ipv6_hdr);
  print_icmpv6_header(icmp6_hdr);

  uint8_t tmp_mac[ETH_ALEN];
  memcpy(tmp_mac, eth_hdr->h_dest, ETH_ALEN);
  memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
  memcpy(eth_hdr->h_source, tmp_mac, ETH_ALEN);

  struct in6_addr tmp_ip;
  memcpy(&tmp_ip, &ipv6_hdr->ip6_src, sizeof(tmp_ip));
  memcpy(&ipv6_hdr->ip6_src, &ipv6_hdr->ip6_dst, sizeof(tmp_ip));
  memcpy(&ipv6_hdr->ip6_src, &tmp_ip, sizeof(tmp_ip));

  icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST;

  icmp6_hdr->icmp6_cksum = 0;
  uint16_t checksum =
      calc_cksum((uint8_t *)icmp6_hdr,
                 len - sizeof(struct ethhdr) - sizeof(struct ip6_hdr));
  icmp6_hdr->icmp6_cksum = checksum;

  /* Here we sent the packet out of the receive port. Note that
   * we allocate one entry and schedule it. Your design would be
   * faster if you do batch processing/transmission */
  unsigned int tx_idx = 0;
  unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
  if (ret != 1) {
    printf("ICMP6 cannot send reply\n");
    return false;
  }

  printf("ICMP6 (%d) >>>>>>>>\n", tx_idx);
  print_ethernet_header(eth_hdr);
  print_ipv6_header(ipv6_hdr);
  print_icmpv6_header(icmp6_hdr);

  struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
  tx_desc->addr = addr;
  tx_desc->len = len;
  tx_desc->options = 0;
  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;

  return true;
}

static bool process_icmp_v4(struct xsk_socket_info *xsk, uint64_t addr,
                            uint32_t len) {
  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  if (len <
      (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))) {
    return false;
  }

  struct ethhdr *eth_hdr = (struct ethhdr *)pkt;
  struct iphdr *ipv4_hdr = (struct iphdr *)(eth_hdr + 1);
  struct icmphdr *icmpv4_hdr = (struct icmphdr *)(ipv4_hdr + 1);

  int fail_1 = eth_hdr->h_proto != ntohs(ETH_P_IP);
  int fail_2 = ipv4_hdr->protocol != IPPROTO_ICMP;
  int fail_3 = icmpv4_hdr->type != ICMP_ECHO;
  int fail_4 = icmpv4_hdr->code != 0;

  if (fail_1 || fail_2 || fail_3 || fail_4) {
    return false;
  }

  printf("ICMP4 <<<<<<<<\n");
  print_ethernet_header(eth_hdr);
  print_ipv4_header(ipv4_hdr);
  print_icmp_header(icmpv4_hdr);

  uint16_t expected_cksum = icmpv4_hdr->checksum;
  uint32_t calculated_len = len - sizeof(struct ethhdr) - sizeof(struct iphdr);
  uint32_t calculated_len2 = ntohs(ipv4_hdr->tot_len) - sizeof(struct iphdr);

  // Validate checksum
  {
    if (calculated_len != calculated_len2) {
      printf("ipv4_hdr->tot_len %hu calculated_len %d calculated_len2 %d\n",
             ntohs(ipv4_hdr->tot_len), calculated_len, calculated_len2);
      assert(false);
    }
    icmpv4_hdr->checksum = 0;
    uint16_t calculated_cksum =
        calc_cksum((uint8_t *)icmpv4_hdr, calculated_len);
    if (expected_cksum != calculated_cksum) {
      printf("expected_checksum 0x%x calculated 0x%x\n", expected_cksum,
             calculated_cksum);
      assert(false);
    }
  }

  uint8_t tmp_mac[ETH_ALEN];
  memcpy(tmp_mac, eth_hdr->h_dest, ETH_ALEN);
  memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
  memcpy(eth_hdr->h_source, tmp_mac, ETH_ALEN);

  uint32_t tmp_ip;
  memcpy(&tmp_ip, &ipv4_hdr->saddr, sizeof(tmp_ip));
  memcpy(&ipv4_hdr->saddr, &ipv4_hdr->daddr, sizeof(tmp_ip));
  memcpy(&ipv4_hdr->daddr, &tmp_ip, sizeof(tmp_ip));

  icmpv4_hdr->type = ICMP_ECHOREPLY;
  icmpv4_hdr->checksum = 0;
  uint16_t checksum = calc_cksum((uint8_t *)icmpv4_hdr, calculated_len);
  icmpv4_hdr->checksum = checksum;

  unsigned int tx_idx = 0;
  unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
  if (ret != 1) {
    printf("ICMP4 cannot send reply\n");
    return false;
  }

  printf("ICMP4 (%d) >>>>>>>>\n", tx_idx);
  print_ethernet_header(eth_hdr);
  print_ipv4_header(ipv4_hdr);
  print_icmp_header(icmpv4_hdr);

  struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
  tx_desc->addr = addr;
  tx_desc->len = len;
  tx_desc->options = 0;
  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;

  return true;
}

static bool process_arp(struct xsk_socket_info *xsk, uint64_t addr,
                        uint32_t len) {
  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  if (len < (sizeof(struct ethhdr) + sizeof(struct ether_arp))) {
    return false;
  }

  struct ethhdr *eth_hdr = (struct ethhdr *)pkt;
  struct ether_arp *arp_hdr = (struct ether_arp *)(eth_hdr + 1);

  if (eth_hdr->h_proto != htons(ETH_P_ARP)) {
    return false;
  }

  static_assert(sizeof(unsigned short) == 2, "helo");
  static_assert(sizeof(uint16_t) == 2, "helo");

  printf("ARP <<<<<<\n");
  print_ethernet_header(eth_hdr);
  print_arp_header(arp_hdr);

  // GARP request
  if (arp_hdr->ea_hdr.ar_op == ARPOP_REQUEST &&     //
      arp_hdr->arp_tpa[3] == arp_hdr->arp_spa[3] && //
      arp_hdr->arp_tpa[2] == arp_hdr->arp_spa[2] && //
      arp_hdr->arp_tpa[1] == arp_hdr->arp_spa[1] && //
      arp_hdr->arp_tpa[0] == arp_hdr->arp_spa[0] && //
      arp_hdr->arp_tha[5] == 0 &&                   //
      arp_hdr->arp_tha[4] == 0 &&                   //
      arp_hdr->arp_tha[3] == 0 &&                   //
      arp_hdr->arp_tha[2] == 0 &&                   //
      arp_hdr->arp_tha[1] == 0 &&                   //
      arp_hdr->arp_tha[0] == 0                      //
  ) {
    printf("ARP GARP request\n");
    return true;
  }

  // GARP reply
  if (arp_hdr->ea_hdr.ar_op == ARPOP_REPLY &&       //
      arp_hdr->arp_tpa[3] == arp_hdr->arp_spa[3] && //
      arp_hdr->arp_tpa[2] == arp_hdr->arp_spa[2] && //
      arp_hdr->arp_tpa[1] == arp_hdr->arp_spa[1] && //
      arp_hdr->arp_tpa[0] == arp_hdr->arp_spa[0] && //
      arp_hdr->arp_tha[5] == arp_hdr->arp_sha[5] && //
      arp_hdr->arp_tha[4] == arp_hdr->arp_sha[4] && //
      arp_hdr->arp_tha[3] == arp_hdr->arp_sha[3] && //
      arp_hdr->arp_tha[2] == arp_hdr->arp_sha[2] && //
      arp_hdr->arp_tha[1] == arp_hdr->arp_sha[1] && //
      arp_hdr->arp_tha[0] == arp_hdr->arp_sha[0]    //
  ) {
    printf("ARP GARP reply\n");
    return true;
  }

  unsigned int tx_idx = 0;
  unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
  if (ret != 1) {
    printf("ARP cannot send reply\n");
    return false;
  }

  arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);
  // uint8_t tmp_tha[ETH_ALEN];
  char *our_MAC_address = "\xca\x88\x4f\xae\xd1\x61";
  uint8_t tmp_tpa[4];
  // memcpy(&tmp_tha, &arp->arp_tha, ETH_ALEN);

  memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
  memcpy(eth_hdr->h_source, our_MAC_address, ETH_ALEN);
  memcpy(&tmp_tpa, &arp_hdr->arp_tpa, 4);
  memcpy(&arp_hdr->arp_tha, &arp_hdr->arp_sha, ETH_ALEN);
  memcpy(&arp_hdr->arp_tpa, &arp_hdr->arp_spa, 4);
  memcpy(&arp_hdr->arp_sha, our_MAC_address, ETH_ALEN);
  memcpy(&arp_hdr->arp_spa, &tmp_tpa, 4);

  printf("ARP >>>>>>>>\n");
  print_ethernet_header(eth_hdr);
  print_arp_header(arp_hdr);

  struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
  tx_desc->addr = addr;
  tx_desc->len = len;
  tx_desc->options = 0;
  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;

  return true;
}

static bool process_ipv4_tcp(struct xsk_socket_info *xsk, uint64_t addr,
                             uint32_t len) {
  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  if (len <
      (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))) {
    return false;
  }

  struct ethhdr *eth_hdr = (struct ethhdr *)pkt;
  struct iphdr *ipv4_hdr = (struct iphdr *)(eth_hdr + 1);
  struct tcphdr *tcp_hdr = (struct tcphdr *)(ipv4_hdr + 1);

  if (eth_hdr->h_proto != htons(ETH_P_IP)) {
    return false;
  }

  if (ipv4_hdr->protocol != IPPROTO_TCP) {
    return false;
  }

  printf("TCP <<<<<<<<\n");
  print_ethernet_header(eth_hdr);
  print_ipv4_header(ipv4_hdr);
  print_tcp_header(tcp_hdr);

  return true;
}

uint8_t sent = 0;

static bool tcp_init(struct xsk_socket_info *xsk) {

  if (sent == 1) {
    return false;
  }
  sent = 1;

  printf("tcp_init\n");

  unsigned int tx_idx = 0;
  unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
  if (ret != 1) {
    printf("tcp_init: Unable to reserve XSK producer\n");
    return false;
  }

  const size_t payload_len =
      sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + 4;

  // printf("payload_len:%zu\n", payload_len);
  // printf("tx_idx:%u\n", tx_idx);

  struct xdp_desc *xdp_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
  char *buffer = xsk_umem__get_data(xsk->umem->buffer, xdp_desc->addr);
  xdp_desc->len = payload_len;
  memset(buffer, 0, payload_len);

  // printf("xdp_desc.addr:%llu\n", xdp_desc->addr);
  // printf("xdp_desc.len:%u\n", xdp_desc->len);

  // struct ethhdr *eth_hdr = (struct ethhdr *)buffer;
  // struct iphdr *ipv4_hdr = (struct iphdr *)(eth_hdr + 1);
  // struct tcphdr *tcp_hdr = (struct tcphdr *)(ipv4_hdr + 1);
  // char *tcp_options = (char *)(tcp_hdr + 1);
  struct ethhdr eth_hdr_v;
  struct iphdr ipv4_hdr_v;
  struct tcphdr tcp_hdr_v;
  char tcp_options_v[4];
  struct ethhdr *eth_hdr = &eth_hdr_v;
  struct iphdr *ipv4_hdr = &ipv4_hdr_v;
  struct tcphdr *tcp_hdr = &tcp_hdr_v;
  char *tcp_options = tcp_options_v;
  memset(eth_hdr, 0, sizeof(struct ethhdr));
  memset(ipv4_hdr, 0, sizeof(struct iphdr));
  memset(tcp_hdr, 0, sizeof(struct tcphdr));
  memset(tcp_options_v, 0, 4);

  // uint64_t diff1 = (uint64_t)(void *)ipv4_hdr - (uint64_t)(void *)(eth_hdr);
  // uint64_t diff2 = (uint64_t)(void *)tcp_hdr - (uint64_t)(void *)(ipv4_hdr);
  // printf("ethhdr:%lu\n", sizeof(struct ethhdr));
  // printf("iphdr:%lu\n", sizeof(struct iphdr));
  // printf("tcphdr:%lu\n", sizeof(struct tcphdr));
  // printf("diff1:%lu\n", diff1);
  // printf("diff2:%lu\n", diff2);

  assert(sizeof(eth_hdr->h_dest) == strlen(DST_MAC));
  assert(sizeof(eth_hdr->h_source) == strlen(SRC_MC));

  // ETHERNET TYPE II
  memcpy(&eth_hdr->h_dest, DST_MAC, strlen(DST_MAC));
  memcpy(&eth_hdr->h_source, SRC_MC, strlen(SRC_MC));
  eth_hdr->h_proto = htons(ETH_P_IP);

  // IPV4
  uint32_t n_saddr = 0;
  uint32_t n_daddr = 0;
  assert(inet_pton(AF_INET, "10.11.1.2", &n_saddr) == 1);
  assert(inet_pton(AF_INET, "10.11.1.1", &n_daddr) == 1);
  static_assert(sizeof(struct iphdr) + sizeof(struct tcphdr) == 40, "mismatch");

  time_t seconds = time(NULL);

  ipv4_hdr->ihl = 5;
  ipv4_hdr->version = 4;
  ipv4_hdr->tot_len = htons(44);
  ipv4_hdr->id = htons(seconds % 4096);
  ipv4_hdr->frag_off = htons(0x4000);
  ipv4_hdr->ttl = 64;
  ipv4_hdr->protocol = 6;
  ipv4_hdr->saddr = n_saddr;
  ipv4_hdr->daddr = n_daddr;

  {
    ipv4_hdr->check = 0;
    uint16_t cksum = calc_cksum((uint8_t *)ipv4_hdr, sizeof(struct iphdr));
    ipv4_hdr->check = cksum;
  }

  // TCP
  tcp_hdr->th_sport = htons((seconds % 4096) + 4096);
  tcp_hdr->th_dport = htons(8080);
  tcp_hdr->th_seq = seconds % 4096;
  tcp_hdr->th_off = 6;
  tcp_hdr->th_flags = TH_SYN;
  tcp_hdr->th_win = ntohs(512);
  tcp_hdr->th_seq = ntohl(seconds % (1024 * 1024));

  // TCP Options
  *(tcp_options + 0) = 2;
  *(tcp_options + 1) = 4;
  *(uint16_t *)(tcp_options + 2) = ntohs(0x05B4);

  {
    struct pseudo_tcphdr {
      uint32_t saddr;
      uint32_t daddr;
      uint8_t zero;
      uint8_t proto;
      uint16_t len;
    };
    char *ss = malloc(sizeof(struct pseudo_tcphdr) + sizeof(struct tcphdr) + 4);
    struct pseudo_tcphdr *hdr1 = (struct pseudo_tcphdr *)(ss);
    hdr1->saddr = n_saddr;
    hdr1->daddr = n_daddr;
    hdr1->proto = ipv4_hdr->protocol;
    hdr1->len = htons(24);
    struct tcphdr *hdr2 = (struct tcphdr *)(hdr1 + 1);
    memcpy(ss + sizeof(struct pseudo_tcphdr), (char *)tcp_hdr,
           sizeof(struct tcphdr));
    memcpy(ss + sizeof(struct pseudo_tcphdr) + sizeof(struct tcphdr),
           (char *)tcp_options, 4);

    // printf("saddr->%x\n", ntohl(hdr1->saddr));
    // printf("daddr->%x\n", ntohl(hdr1->daddr));
    // printf("proto->%d\n", hdr1->proto);
    // printf("len->%d\n", ntohs(hdr1->len));

    // print_tcp_header(hdr2);
    // printf("saddr->%x\n", n_saddr);
    // printf("saddr->%x\n", ntohl(hdr1->saddr));
    // printf("daddr->%x\n", ntohl(hdr1->daddr));
    // printf("proto->%d\n", hdr1->proto);
    // printf("len->%d\n", ntohs(hdr1->len));
    // printf("daddr->%d", hdr1->saddr);

    tcp_hdr->check = 0;
    uint16_t cksum = calc_cksum((uint8_t *)ss, sizeof(struct pseudo_tcphdr) +
                                                   sizeof(struct tcphdr) + 4);
    tcp_hdr->check = cksum;
    free(ss);
  }

  // the rest of it...

  printf("TCP (%d) >>>>>>>>\n", tx_idx);
  print_ethernet_header(eth_hdr);
  print_ipv4_header(ipv4_hdr);
  print_tcp_header(tcp_hdr);

  // memcpy to the buffer
  memcpy(buffer, eth_hdr, sizeof(struct ethhdr));
  memcpy(buffer + sizeof(struct ethhdr), ipv4_hdr, sizeof(struct iphdr));
  memcpy(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr), tcp_hdr,
         sizeof(struct tcphdr));
  memcpy(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) +
             sizeof(struct tcphdr),
         tcp_options, 4);

  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;

  complete_tx(xsk);
  return true;
}

static bool tcp_send_data(struct xsk_socket_info *xsk) {
  // printf("tcp_init\n");
  if (sent == 1) {
    return false;
  }
  sent = 1;

  printf("tcp_init\n");

  unsigned int tx_idx = 0;
  unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
  if (ret != 1) {
    printf("tcp_init: Unable to reserve XSK producer\n");
    return false;
  }

  const size_t payload_len =
      sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

  // printf("payload_len:%zu\n", payload_len);
  // printf("tx_idx:%u\n", tx_idx);

  struct xdp_desc *xdp_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
  char *buffer = xsk_umem__get_data(xsk->umem->buffer, xdp_desc->addr);
  xdp_desc->len = payload_len;
  memset(buffer, 0, payload_len);

  // printf("xdp_desc.addr:%llu\n", xdp_desc->addr);
  // printf("xdp_desc.len:%u\n", xdp_desc->len);

  struct ethhdr *eth_hdr = (struct ethhdr *)buffer;
  struct iphdr *ipv4_hdr = (struct iphdr *)(eth_hdr + 1);
  struct tcphdr *tcp_hdr = (struct tcphdr *)(ipv4_hdr + 1);

  // struct ethhdr *eth_hdr = (struct ethhdr *)buffer;
  // struct iphdr *ipv4_hdr = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  // struct tcphdr *tcp_hdr =
  //     (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct
  //     iphdr));

  uint64_t diff1 = (uint64_t)(void *)ipv4_hdr - (uint64_t)(void *)(eth_hdr);
  uint64_t diff2 = (uint64_t)(void *)tcp_hdr - (uint64_t)(void *)(ipv4_hdr);

  // printf("ethhdr:%lu\n", sizeof(struct ethhdr));
  // printf("iphdr:%lu\n", sizeof(struct iphdr));
  // printf("tcphdr:%lu\n", sizeof(struct tcphdr));
  // printf("diff1:%lu\n", diff1);
  // printf("diff2:%lu\n", diff2);

  assert(sizeof(eth_hdr->h_dest) == strlen(DST_MAC));
  assert(sizeof(eth_hdr->h_source) == strlen(SRC_MC));

  // ETHERNET TYPE II
  memcpy(&eth_hdr->h_dest, DST_MAC, strlen(DST_MAC));
  memcpy(&eth_hdr->h_source, SRC_MC, strlen(SRC_MC));
  eth_hdr->h_proto = htons(ETH_P_IP);

  // IPV4
  uint32_t src_addr = 0;
  uint32_t dst_addr = 0;
  assert(inet_pton(AF_INET, "10.11.1.2", &src_addr) == 1);
  assert(inet_pton(AF_INET, "10.11.1.1", &dst_addr) == 1);
  static_assert(sizeof(struct iphdr) + sizeof(struct tcphdr) == 40, "mismatch");

  ipv4_hdr->ihl = 5;
  ipv4_hdr->version = 4;
  ipv4_hdr->tot_len = htons(40);
  ipv4_hdr->id = htons(4321);
  ipv4_hdr->frag_off = htons(0x4000);
  ipv4_hdr->ttl = 64;
  ipv4_hdr->protocol = 6;
  ipv4_hdr->saddr = src_addr;
  ipv4_hdr->daddr = dst_addr;

  {
    ipv4_hdr->check = 0;
    uint16_t calculated_checksum =
        calc_cksum((uint8_t *)ipv4_hdr, sizeof(struct iphdr));
    ipv4_hdr->check = calculated_checksum;
  }

  // TCP
  tcp_hdr->th_sport = htons(9090);
  tcp_hdr->th_dport = htons(8080);
  tcp_hdr->th_seq = 1;
  tcp_hdr->th_off = 5;
  tcp_hdr->th_flags = TH_SYN;
  tcp_hdr->th_win = ntohs(512);
  tcp_hdr->th_seq = ntohl(0x10101010);

  // the rest of it...

  printf("TCP (%d) >>>>>>>>\n", tx_idx);
  print_ethernet_header(eth_hdr);
  print_ipv4_header(ipv4_hdr);
  print_tcp_header(tcp_hdr);

  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;

  complete_tx(xsk);
  return true;
}

static bool handle_recv(struct xsk_socket_info *xsk, uint64_t addr,
                        uint32_t len) {
  printf("handle_recv\n");
  bool is_ok = false;
  is_ok = process_icmp_v6(xsk, addr, len);
  if (is_ok) {
    return true;
  }

  is_ok = process_icmp_v4(xsk, addr, len);
  if (is_ok) {
    return true;
  }

  is_ok = process_arp(xsk, addr, len);
  if (is_ok) {
    return true;
  }

  is_ok = process_ipv4_tcp(xsk, addr, len);
  if (is_ok) {
    return true;
  }

  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
  struct ethhdr *eth = (struct ethhdr *)pkt;
  printf("UNKNOWN eth_proto:0x%X\n", ntohs(eth->h_proto));

  return false;
}

static void inner_main_loop(struct xsk_socket_info *xsk) {
  // printf("inner_main_loop\n");
  unsigned int rcvd, stock_frames, i;
  uint32_t idx_rx = 0, idx_fq = 0;
  int ret;

  tcp_init(xsk);

  rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
  if (!rcvd) {
    // printf("no free RX\n");
    return;
  }

  /* Stuff the ring with as much frames as possible */
  stock_frames = xsk_prod_nb_free(&xsk->umem->fq, xsk_umem_free_frames(xsk));

  if (stock_frames > 0) {

    ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames, &idx_fq);

    /* This should not happen, but just in case */
    while (ret != stock_frames) {
      // printf("reserving TX %d %d\n", ret, stock_frames);
      ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
    }

    for (i = 0; i < stock_frames; i++)
      *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
          xsk_alloc_umem_frame(xsk);

    xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
  }

  /* Process received packets */
  for (i = 0; i < rcvd; i++) {
    uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
    uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

    if (!handle_recv(xsk, addr, len)) {
      xsk_free_umem_frame(xsk, addr);
    }
  }

  xsk_ring_cons__release(&xsk->rx, rcvd);

  /* Do we need to wake up the kernel for transmission */
  complete_tx(xsk);
}

static void main_loop(struct config *cfg, struct xsk_socket_info *xsk_socket) {
  printf("main_loop\n");
  struct pollfd fds[2];
  int ret, nfds = 1;

  memset(fds, 0, sizeof(fds));
  fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
  fds[0].events = POLLIN;

  while (!global_exit) {
    if (cfg->xsk_poll_mode) {
      ret = poll(fds, nfds, -1);
      if (ret <= 0 || ret > 1)
        continue;
    }
    inner_main_loop(xsk_socket);
  }
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void) {
  struct timespec t;
  int res;

  res = clock_gettime(CLOCK_MONOTONIC, &t);
  if (res < 0) {
    fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
    exit(EXIT_FAIL);
  }
  return (uint64_t)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static void exit_application(int signal) {
  int err;

  cfg.unload_all = true;
  err = do_unload(&cfg);
  if (err) {
    fprintf(stderr, "Couldn't detach XDP program on iface '%s' : (%d)\n",
            cfg.ifname, err);
  }

  signal = signal;
  global_exit = true;
}

int main(int argc, char **argv) {
  int ret;
  void *packet_buffer;
  uint64_t packet_buffer_size;
  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
  DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
  struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
  struct xsk_umem_info *umem;
  struct xsk_socket_info *xsk_socket;
  pthread_t stats_poll_thread;
  int err;
  char errmsg[1024];

  /* Global shutdown handler */
  signal(SIGINT, exit_application);

  /* Cmdline options can change progname */
  parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

  /* Required option */
  if (cfg.ifindex == -1) {
    fprintf(stderr, "ERROR: Required option --dev missing\n\n");
    usage(argv[0], __doc__, long_options, (argc == 1));
    return EXIT_FAIL_OPTION;
  }

  /* Load custom program if configured */
  if (cfg.filename[0] != 0) {
    struct bpf_map *map;

    custom_xsk = true;
    xdp_opts.open_filename = cfg.filename;
    xdp_opts.prog_name = cfg.progname;
    xdp_opts.opts = &opts;

    if (cfg.progname[0] != 0) {
      xdp_opts.open_filename = cfg.filename;
      xdp_opts.prog_name = cfg.progname;
      xdp_opts.opts = &opts;

      prog = xdp_program__create(&xdp_opts);
    } else {
      prog = xdp_program__open_file(cfg.filename, NULL, &opts);
    }
    err = libxdp_get_error(prog);
    if (err) {
      libxdp_strerror(err, errmsg, sizeof(errmsg));
      fprintf(stderr, "ERR: loading program: %s\n", errmsg);
      return err;
    }

    err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
    if (err) {
      libxdp_strerror(err, errmsg, sizeof(errmsg));
      fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
              cfg.ifname, errmsg, err);
      return err;
    }

    /* We also need to load the xsks_map */
    map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
    xsk_map_fd = bpf_map__fd(map);
    if (xsk_map_fd < 0) {
      fprintf(stderr, "ERROR: no xsks map found: %s\n", strerror(xsk_map_fd));
      exit(EXIT_FAILURE);
    }
  }

  /* Allow unlimited locking of memory, so all memory needed for packet
   * buffers can be locked.
   */
  if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
    fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Allocate memory for NUM_FRAMES of the default XDP frame size */
  packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
  if (posix_memalign(&packet_buffer, getpagesize(), /* PAGE_SIZE aligned */
                     packet_buffer_size)) {
    fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Initialize shared packet_buffer for umem usage */
  umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
  if (umem == NULL) {
    fprintf(stderr, "ERROR: Can't create umem \"%s\"\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Open and configure the AF_XDP (xsk) socket */
  xsk_socket = xsk_configure_socket(&cfg, umem);
  if (xsk_socket == NULL) {
    fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  main_loop(&cfg, xsk_socket);

  /* Cleanup */
  xsk_socket__delete(xsk_socket->xsk);
  xsk_umem__delete(umem->umem);

  return EXIT_OK;
}
