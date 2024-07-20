/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
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
struct stats_record {
  uint64_t timestamp;
  uint64_t rx_packets;
  uint64_t rx_bytes;
  uint64_t tx_packets;
  uint64_t tx_bytes;
};
struct xsk_socket_info {
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_umem_info *umem;
  struct xsk_socket *xsk;

  uint64_t umem_frame_addr[NUM_FRAMES];
  uint32_t umem_frame_free;

  uint32_t outstanding_tx;

  struct stats_record stats;
  struct stats_record prev_stats;
};

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

  if (!xsk->outstanding_tx)
    return;

  sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

  /* Collect/free completed TX buffers */
  completed = xsk_ring_cons__peek(&xsk->umem->cq,
                                  XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

  if (completed > 0) {
    for (int i = 0; i < completed; i++)
      xsk_free_umem_frame(xsk,
                          *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++));

    xsk_ring_cons__release(&xsk->umem->cq, completed);
    xsk->outstanding_tx -=
        completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
  }
}

static inline uint16_t calculate_internet_checksum(uint8_t *addr,
                                                   uint32_t count) {
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

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (~sum);
}

static bool process_icmp_v6(struct xsk_socket_info *xsk, uint64_t addr,
                            uint32_t len) {
  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  if (len < (sizeof(struct ethhdr) + sizeof(struct ip6_hdr) +
             sizeof(struct icmp6_hdr))) {
    return false;
  }

  struct ethhdr *eth = (struct ethhdr *)pkt;
  struct ip6_hdr *ipv6 = (struct ip6_hdr *)(eth + 1);
  struct icmp6_hdr *icmp = (struct icmp6_hdr *)(ipv6 + 1);

  if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
      ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6 ||
      icmp->icmp6_type != ICMP6_ECHO_REQUEST) {
    return false;
  }

  printf("ICMP6 <<<<<<<<<<<<<<<<\n"
         "eth_proto:0x%X\n"
         "eth_dest:0x%X:%X:%X:%X:%X:%X\n"
         "arp_src:0x%X:%X:%X:%X:%X:%X\n"
         "ipv6_proto:0x%X\n"
         "icmp_proto:0x%X\n",
         ntohs(eth->h_proto),                 //
         eth->h_dest[0],                      //
         eth->h_dest[1],                      //
         eth->h_dest[2],                      //
         eth->h_dest[3],                      //
         eth->h_dest[4],                      //
         eth->h_dest[5],                      //
         eth->h_source[0],                    //
         eth->h_source[1],                    //
         eth->h_source[2],                    //
         eth->h_source[3],                    //
         eth->h_source[4],                    //
         eth->h_source[5],                    //
         ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt, //
         icmp->icmp6_type                     //
  );

  uint8_t tmp_mac[ETH_ALEN];
  memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
  memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
  memcpy(eth->h_source, tmp_mac, ETH_ALEN);

  struct in6_addr tmp_ip;
  memcpy(&tmp_ip, &ipv6->ip6_src, sizeof(tmp_ip));
  memcpy(&ipv6->ip6_src, &ipv6->ip6_dst, sizeof(tmp_ip));
  memcpy(&ipv6->ip6_src, &tmp_ip, sizeof(tmp_ip));

  icmp->icmp6_type = ICMP6_ECHO_REQUEST;

  icmp->icmp6_cksum = 0;
  uint16_t checksum = calculate_internet_checksum(
      (uint8_t *)&icmp, len - sizeof(struct ethhdr) - sizeof(struct ip6_hdr));
  icmp->icmp6_cksum = checksum;

  /* Here we sent the packet out of the receive port. Note that
   * we allocate one entry and schedule it. Your design would be
   * faster if you do batch processing/transmission */
  unsigned int tx_idx = 0;
  unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
  if (ret != 1) {
    printf("ICMP6 cannot send reply\n");
    return false;
  }

  printf("ICMP6 >>>>>>>>>>>>>>>>>>>>\n"
         "eth_proto:0x%X\n"
         "eth_dest:0x%X:%X:%X:%X:%X:%X\n"
         "arp_src:0x%X:%X:%X:%X:%X:%X\n"
         "ipv6_proto:0x%X\n"
         "icmp_proto:0x%X\n",
         ntohs(eth->h_proto),                 //
         eth->h_dest[0],                      //
         eth->h_dest[1],                      //
         eth->h_dest[2],                      //
         eth->h_dest[3],                      //
         eth->h_dest[4],                      //
         eth->h_dest[5],                      //
         eth->h_source[0],                    //
         eth->h_source[1],                    //
         eth->h_source[2],                    //
         eth->h_source[3],                    //
         eth->h_source[4],                    //
         eth->h_source[5],                    //
         ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt, //
         icmp->icmp6_type                     //
  );

  struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
  tx_desc->addr = addr;
  tx_desc->len = len;
  tx_desc->options = 0;
  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;

  xsk->stats.tx_bytes += len;
  xsk->stats.tx_packets++;
  return true;
}

static bool process_icmp_v4(struct xsk_socket_info *xsk, uint64_t addr,
                            uint32_t len) {
  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  if (len <
      (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))) {
    return false;
  }

  struct ethhdr *eth = (struct ethhdr *)pkt;
  struct iphdr *ipv4 = (struct iphdr *)(eth + 1);
  struct icmphdr *icmp = (struct icmphdr *)(ipv4 + 1);

  int fail_1 = ntohs(eth->h_proto) != ETH_P_IP;
  int fail_2 = ipv4->protocol != IPPROTO_ICMP;
  int fail_3 = icmp->type != ICMP_ECHO;
  int fail_4 = icmp->code != 0;

  // printf("ICMP4 %d %d %d %d\n", fail_1, fail_2, fail_3, fail_4);

  if (fail_1 || fail_2 || fail_3 || fail_4) {
    return false;
  }

  printf("ICMP4 <<<<<<<<<<<<<<<<\n"
         "eth_proto:0x%X\n"
         "eth_dest:0x%X:%X:%X:%X:%X:%X\n"
         "arp_src:0x%X:%X:%X:%X:%X:%X\n"
         "ipv4_proto:0x%X\n"
         "icmp_proto:0x%X\n"
         "icmp_code:0x%X\n",
         ntohs(eth->h_proto), //
         eth->h_dest[0],      //
         eth->h_dest[1],      //
         eth->h_dest[2],      //
         eth->h_dest[3],      //
         eth->h_dest[4],      //
         eth->h_dest[5],      //
         eth->h_source[0],    //
         eth->h_source[1],    //
         eth->h_source[2],    //
         eth->h_source[3],    //
         eth->h_source[4],    //
         eth->h_source[5],    //
         ipv4->protocol,      //
         icmp->type,          //
         icmp->code           //
  );

  uint8_t tmp_mac[ETH_ALEN];
  memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
  memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
  memcpy(eth->h_source, tmp_mac, ETH_ALEN);

  uint32_t tmp_ip;
  memcpy(&tmp_ip, &ipv4->saddr, sizeof(tmp_ip));
  memcpy(&ipv4->saddr, &ipv4->daddr, sizeof(tmp_ip));
  memcpy(&ipv4->daddr, &tmp_ip, sizeof(tmp_ip));

  icmp->type = ICMP_ECHOREPLY;
  icmp->checksum = 0;
  uint16_t checksum = calculate_internet_checksum(
      (uint8_t *)&icmp, len - sizeof(struct ethhdr) - sizeof(struct iphdr));
  icmp->checksum = checksum;

  unsigned int tx_idx = 0;
  unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
  if (ret != 1) {
    printf("ICMP4 cannot send reply\n");
    return false;
  }

  printf("ICMP4 >>>>>>>>>>>>>>>\n"
         "eth_proto:0x%X\n"
         "eth_dest:0x%X:%X:%X:%X:%X:%X\n"
         "arp_src:0x%X:%X:%X:%X:%X:%X\n"
         "ipv4_proto:0x%X\n"
         "icmp_proto:0x%X\n"
         "icmp_code:0x%X\n",
         ntohs(eth->h_proto), //
         eth->h_dest[0],      //
         eth->h_dest[1],      //
         eth->h_dest[2],      //
         eth->h_dest[3],      //
         eth->h_dest[4],      //
         eth->h_dest[5],      //
         eth->h_source[0],    //
         eth->h_source[1],    //
         eth->h_source[2],    //
         eth->h_source[3],    //
         eth->h_source[4],    //
         eth->h_source[5],    //
         ipv4->protocol,      //
         icmp->type,          //
         icmp->code           //
  );

  struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
  tx_desc->addr = addr;
  tx_desc->len = len;
  tx_desc->options = 0;
  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;

  xsk->stats.tx_bytes += len;
  xsk->stats.tx_packets++;
  return true;
}

static bool process_arp_v4(struct xsk_socket_info *xsk, uint64_t addr,
                           uint32_t len) {
  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  if (len < (sizeof(struct ethhdr) + sizeof(struct ether_arp))) {
    return false;
  }

  struct ethhdr *eth = (struct ethhdr *)pkt;
  struct ether_arp *arp = (struct ether_arp *)(eth + 1);

  if (ntohs(eth->h_proto) != ETH_P_ARP) {
    return false;
  }

  static_assert(sizeof(unsigned short) == 2);
  static_assert(sizeof(uint16_t) == 2);

  printf("ARP <<<<<<<<<<<<\n"
         "eth_proto:0x%X\n"
         "eth_dest:0x%X:%X:%X:%X:%X:%X\n"
         "arp_src:0x%X:%X:%X:%X:%X:%X\n"
         "eth_ar_hrd:0x%X\n"
         "eth_ar_pro:0x%X\n"
         "eth_ar_hln:0x%X\n"
         "eth_ar_pln:0x%X\n"
         "eth_ar_op:0x%X\n"
         "arp_sha:0x%X:%X:%X:%X:%X:%X\n"
         "arp_spa:0x%X:%X:%X:%X\n"
         "arp_tha:0x%X:%X:%X:%X:%X:%X\n"
         "arp_tpa:0x%X:%X:%X:%X\n",
         ntohs(eth->h_proto),       //
         eth->h_dest[0],            //
         eth->h_dest[1],            //
         eth->h_dest[2],            //
         eth->h_dest[3],            //
         eth->h_dest[4],            //
         eth->h_dest[5],            //
         eth->h_source[0],          //
         eth->h_source[1],          //
         eth->h_source[2],          //
         eth->h_source[3],          //
         eth->h_source[4],          //
         eth->h_source[5],          //
         ntohs(arp->ea_hdr.ar_hrd), //
         ntohs(arp->ea_hdr.ar_pro), //
         arp->ea_hdr.ar_hln,        //
         arp->ea_hdr.ar_pln,        //
         ntohs(arp->ea_hdr.ar_op),  //
         arp->arp_sha[0],           //
         arp->arp_sha[1],           //
         arp->arp_sha[2],           //
         arp->arp_sha[3],           //
         arp->arp_sha[4],           //
         arp->arp_sha[5],           //
         arp->arp_spa[0],           //
         arp->arp_spa[1],           //
         arp->arp_spa[2],           //
         arp->arp_spa[3],           //
         arp->arp_tha[0],           //
         arp->arp_tha[1],           //
         arp->arp_tha[2],           //
         arp->arp_tha[3],           //
         arp->arp_tha[4],           //
         arp->arp_tha[5],           //
         arp->arp_tpa[0],           //
         arp->arp_tpa[1],           //
         arp->arp_tpa[2],           //
         arp->arp_tpa[3]            //
  );

  // GARP request
  if (arp->ea_hdr.ar_op == ARPOP_REQUEST && //
      arp->arp_tpa[3] == arp->arp_spa[3] && //
      arp->arp_tpa[2] == arp->arp_spa[2] && //
      arp->arp_tpa[1] == arp->arp_spa[1] && //
      arp->arp_tpa[0] == arp->arp_spa[0] && //
      arp->arp_tha[5] == 0 &&               //
      arp->arp_tha[4] == 0 &&               //
      arp->arp_tha[3] == 0 &&               //
      arp->arp_tha[2] == 0 &&               //
      arp->arp_tha[1] == 0 &&               //
      arp->arp_tha[0] == 0                  //
  ) {
    printf("ARP GARP request\n");
    return true;
  }

  // GARP reply
  if (arp->ea_hdr.ar_op == ARPOP_REPLY &&   //
      arp->arp_tpa[3] == arp->arp_spa[3] && //
      arp->arp_tpa[2] == arp->arp_spa[2] && //
      arp->arp_tpa[1] == arp->arp_spa[1] && //
      arp->arp_tpa[0] == arp->arp_spa[0] && //
      arp->arp_tha[5] == arp->arp_sha[5] && //
      arp->arp_tha[4] == arp->arp_sha[4] && //
      arp->arp_tha[3] == arp->arp_sha[3] && //
      arp->arp_tha[2] == arp->arp_sha[2] && //
      arp->arp_tha[1] == arp->arp_sha[1] && //
      arp->arp_tha[0] == arp->arp_sha[0]    //
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

  arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
  // uint8_t tmp_tha[ETH_ALEN];
  char *our_MAC_address = "\xca\x88\x4f\xae\xd1\x61";
  uint8_t tmp_tpa[4];
  // memcpy(&tmp_tha, &arp->arp_tha, ETH_ALEN);

  memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
  memcpy(eth->h_source, our_MAC_address, ETH_ALEN);
  memcpy(&tmp_tpa, &arp->arp_tpa, 4);
  memcpy(&arp->arp_tha, &arp->arp_sha, ETH_ALEN);
  memcpy(&arp->arp_tpa, &arp->arp_spa, 4);
  memcpy(&arp->arp_sha, our_MAC_address, ETH_ALEN);
  memcpy(&arp->arp_spa, &tmp_tpa, 4);

  printf("ARP >>>>>>>>>>>>>>>\n"
         "eth_proto:0x%X\n"
         "eth_dest:0x%X:%X:%X:%X:%X:%X\n"
         "arp_src:0x%X:%X:%X:%X:%X:%X\n"
         "eth_ar_hrd:0x%X\n"
         "eth_ar_pro:0x%X\n"
         "eth_ar_hln:0x%X\n"
         "eth_ar_pln:0x%X\n"
         "eth_ar_op:0x%X\n"
         "arp_sha:0x%X:%X:%X:%X:%X:%X\n"
         "arp_spa:0x%X:%X:%X:%X\n"
         "arp_tha:0x%X:%X:%X:%X:%X:%X\n"
         "arp_tpa:0x%X:%X:%X:%X\n",
         ntohs(eth->h_proto),       //
         eth->h_dest[0],            //
         eth->h_dest[1],            //
         eth->h_dest[2],            //
         eth->h_dest[3],            //
         eth->h_dest[4],            //
         eth->h_dest[5],            //
         eth->h_source[0],          //
         eth->h_source[1],          //
         eth->h_source[2],          //
         eth->h_source[3],          //
         eth->h_source[4],          //
         eth->h_source[5],          //
         ntohs(arp->ea_hdr.ar_hrd), //
         ntohs(arp->ea_hdr.ar_pro), //
         arp->ea_hdr.ar_hln,        //
         arp->ea_hdr.ar_pln,        //
         ntohs(arp->ea_hdr.ar_op),  //
         arp->arp_sha[0],           //
         arp->arp_sha[1],           //
         arp->arp_sha[2],           //
         arp->arp_sha[3],           //
         arp->arp_sha[4],           //
         arp->arp_sha[5],           //
         arp->arp_spa[0],           //
         arp->arp_spa[1],           //
         arp->arp_spa[2],           //
         arp->arp_spa[3],           //
         arp->arp_tha[0],           //
         arp->arp_tha[1],           //
         arp->arp_tha[2],           //
         arp->arp_tha[3],           //
         arp->arp_tha[4],           //
         arp->arp_tha[5],           //
         arp->arp_tpa[0],           //
         arp->arp_tpa[1],           //
         arp->arp_tpa[2],           //
         arp->arp_tpa[3]            //
  );

  struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
  tx_desc->addr = addr;
  tx_desc->len = len;
  tx_desc->options = 0;
  xsk_ring_prod__submit(&xsk->tx, 1);
  xsk->outstanding_tx++;

  xsk->stats.tx_bytes += len;
  xsk->stats.tx_packets++;

  return true;
}

static bool process_arp_tcp(struct xsk_socket_info *xsk, uint64_t addr,
                            uint32_t len) {
  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

  if (len < (sizeof(struct ethhdr) + sizeof(struct ether_arp))) {
    return false;
  }

  printf("receive TCP\n");

  return true;
}

static bool process_packet(struct xsk_socket_info *xsk, uint64_t addr,
                           uint32_t len) {
  printf("process packet\n");
  bool is_ok = false;
  is_ok = process_icmp_v6(xsk, addr, len);
  if (is_ok) {
    return true;
  }

  is_ok = process_icmp_v4(xsk, addr, len);
  if (is_ok) {
    return true;
  }

  is_ok = process_arp_v4(xsk, addr, len);
  if (is_ok) {
    return true;
  }

  uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
  struct ethhdr *eth = (struct ethhdr *)pkt;
  printf("UNKNOWN eth_proto:0x%X\n", ntohs(eth->h_proto));

  return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk) {
  unsigned int rcvd, stock_frames, i;
  uint32_t idx_rx = 0, idx_fq = 0;
  int ret;

  rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
  if (!rcvd)
    return;

  /* Stuff the ring with as much frames as possible */
  stock_frames = xsk_prod_nb_free(&xsk->umem->fq, xsk_umem_free_frames(xsk));

  if (stock_frames > 0) {

    ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames, &idx_fq);

    /* This should not happen, but just in case */
    while (ret != stock_frames)
      ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);

    for (i = 0; i < stock_frames; i++)
      *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
          xsk_alloc_umem_frame(xsk);

    xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
  }

  /* Process received packets */
  for (i = 0; i < rcvd; i++) {
    uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
    uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

    if (!process_packet(xsk, addr, len))
      xsk_free_umem_frame(xsk, addr);

    xsk->stats.rx_bytes += len;
  }

  xsk_ring_cons__release(&xsk->rx, rcvd);
  xsk->stats.rx_packets += rcvd;

  /* Do we need to wake up the kernel for transmission */
  complete_tx(xsk);
}

static void rx_and_process(struct config *cfg,
                           struct xsk_socket_info *xsk_socket) {
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
    handle_receive_packets(xsk_socket);
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

static double calc_period(struct stats_record *r, struct stats_record *p) {
  double period_ = 0;
  __u64 period = 0;

  period = r->timestamp - p->timestamp;
  if (period > 0)
    period_ = ((double)period / NANOSEC_PER_SEC);

  return period_;
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev) {
  uint64_t packets, bytes;
  double period;
  double pps; /* packets per sec */
  double bps; /* bits per sec */

  char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
              " %'11lld Kbytes (%'6.0f Mbits/s)"
              " period:%f\n";

  period = calc_period(stats_rec, stats_prev);
  if (period == 0)
    period = 1;

  packets = stats_rec->rx_packets - stats_prev->rx_packets;
  pps = packets / period;

  bytes = stats_rec->rx_bytes - stats_prev->rx_bytes;
  bps = (bytes * 8) / period / 1000000;

  printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
         stats_rec->rx_bytes / 1000, bps, period);

  packets = stats_rec->tx_packets - stats_prev->tx_packets;
  pps = packets / period;

  bytes = stats_rec->tx_bytes - stats_prev->tx_bytes;
  bps = (bytes * 8) / period / 1000000;

  printf(fmt, "       TX:", stats_rec->tx_packets, pps,
         stats_rec->tx_bytes / 1000, bps, period);

  printf("\n");
}

static void *stats_poll(void *arg) {
  unsigned int interval = 2;
  struct xsk_socket_info *xsk = arg;
  static struct stats_record previous_stats = {0};

  previous_stats.timestamp = gettime();

  /* Trick to pretty printf with thousands separators use %' */
  setlocale(LC_NUMERIC, "en_US");

  while (!global_exit) {
    sleep(interval);
    xsk->stats.timestamp = gettime();
    stats_print(&xsk->stats, &previous_stats);
    previous_stats = xsk->stats;
  }
  return NULL;
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

  // /* Start thread to do statistics display */
  // if (verbose) {
  //   ret = pthread_create(&stats_poll_thread, NULL, stats_poll, xsk_socket);
  //   if (ret) {
  //     fprintf(stderr,
  //             "ERROR: Failed creating statistics thread "
  //             "\"%s\"\n",
  //             strerror(errno));
  //     exit(EXIT_FAILURE);
  //   }
  // }

  /* Receive and count packets than drop them */
  rx_and_process(&cfg, xsk_socket);

  /* Cleanup */
  xsk_socket__delete(xsk_socket->xsk);
  xsk_umem__delete(umem->umem);

  return EXIT_OK;
}