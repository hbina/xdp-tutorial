#pragma once

#include "impl_xdp.h"

#define ETH_ALEN 6

struct packed_eth_hdr {
    unsigned char h_dest[ETH_ALEN];   /* destination eth addr	*/
    unsigned char h_source[ETH_ALEN]; /* source ether addr	*/
    __be16 h_proto;                   /* packet type ID field	*/
} __attribute__((packed));
static_assert(sizeof(struct packed_eth_hdr) == 14, "ethernet header is 14 bytes");

struct packed_ipv4_hdr {
    unsigned int ihl : 4;
    unsigned int version : 4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));
static_assert(sizeof(struct packed_ipv4_hdr) == 20, "IPV4 header is 20 bytes");

struct packed_ipv6_hdr {
    struct packed_ipv6ctl_hdr {
        uint32_t ip6_un1_flow; /* 4 bits version, 8 bits TC,
                                  20 bits flow-ID */
        uint16_t ip6_un1_plen; /* payload length */
        uint8_t ip6_un1_nxt;   /* next header */
        uint8_t ip6_un1_hlim;  /* hop limit */
    } __attribute__((packed)) ip6_un1;
    struct in6_addr ip6_src; /* source address */
    struct in6_addr ip6_dst; /* destination address */
} __attribute__((packed));
static_assert(sizeof(struct packed_ipv6_hdr) == 40, "IPV6 header is 40 bytes");

struct packed_tcp_hdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    // uint8_t doff : 4;
    // uint8_t res1 : 4;
    uint8_t doff___;
    // uint8_t fin : 1;
    // uint8_t syn : 1;
    // uint8_t rst : 1;
    // uint8_t psh : 1;
    // uint8_t ack : 1;
    // uint8_t urg : 1;
    // uint8_t res2 : 2;
    uint8_t flag;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));
static_assert(sizeof(struct packed_tcp_hdr) == 20, "TCP header is 20 bytes");

static int packed_tcp_hdr_get_offset(const struct packed_tcp_hdr *s) {
    // assert(s->doff___ != 0);
    return s->doff___ & 0xF0;
}
static void packed_tcp_hdr_set_offset(struct packed_tcp_hdr *s, uint8_t offset) {
    assert(offset != 0);
    s->doff___ = (offset & 0x0F) << 4;
    assert(s->doff___ != 0);
}

struct packed_arp_hdr {
    unsigned short int ar_hrd; /* Format of hardware address.  */
    unsigned short int ar_pro; /* Format of protocol address.  */
    unsigned char ar_hln;      /* Length of hardware address.  */
    unsigned char ar_pln;      /* Length of protocol address.  */
    unsigned short int ar_op;  /* ARP opcode (command).  */
} __attribute__((packed));
static_assert(sizeof(struct packed_arp_hdr) == 8, "ARP header header is 8 bytes");

struct packed_etherarp_hdr {
    struct packed_arp_hdr ea_hdr; /* fixed-size header */
    uint8_t arp_sha[ETH_ALEN];    /* sender hardware address */
    uint8_t arp_spa[4];           /* sender protocol address */
    uint8_t arp_tha[ETH_ALEN];    /* target hardware address */
    uint8_t arp_tpa[4];           /* target protocol address */
} __attribute__((packed));
static_assert(sizeof(struct packed_etherarp_hdr) == 28, "ARP Ethernet header is 28 bytes");

struct packed_icmp4_hdr {
    uint8_t type; /* message type */
    uint8_t code; /* type sub-code */
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed));
static_assert(sizeof(struct packed_icmp4_hdr) == 8, "ICMP IPV4 header is 8 bytes");

struct packed_icmp6_hdr {
    uint8_t icmp6_type;          /* type field */
    uint8_t icmp6_code;          /* code field */
    uint16_t icmp6_cksum;        /* checksum field */
    uint32_t icmp6_un_data32[1]; /* type-specific field */
    uint16_t icmp6_un_data16[2]; /* type-specific field */
    uint8_t icmp6_un_data8[4];   /* type-specific field */
};
static_assert(sizeof(struct packed_icmp6_hdr) == 16, "ICMP IPV4 header is 16 bytes");

static void ethernet_print_header(const struct packed_eth_hdr *eth_hdr) {
    printf("Ethernet Header\n");
    printf("\t|-Destination Address : ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02X%c", eth_hdr->h_dest[i], (i == ETHER_ADDR_LEN - 1) ? ' ' : ':');
    }
    printf("\n");
    printf("\t|-Source Address      : ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02X%c", eth_hdr->h_source[i], (i == ETHER_ADDR_LEN - 1) ? ' ' : ':');
    }
    printf("\n");
    printf("\t|-EtherType           : 0x%04X\n", ntohs(eth_hdr->h_proto));
}

static void ipv4_print_header(const struct packed_ipv4_hdr *ipv4_hdr) {
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipv4_hdr->saddr), src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipv4_hdr->daddr), dst_addr, INET_ADDRSTRLEN);

    printf("IPv4 Header\n");
    printf("\t|-Version              : %d\n", ipv4_hdr->version);
    printf("\t|-Header Length        : %d DWORDS or %d Bytes\n", ipv4_hdr->ihl, ipv4_hdr->ihl * 4);
    printf("\t|-Type of Service      : %d\n", ipv4_hdr->tos);
    printf("\t|-Total Length         : %d Bytes\n", ntohs(ipv4_hdr->tot_len));
    printf("\t|-Identification       : %d\n", ntohs(ipv4_hdr->id));
    printf("\t|-Fragment Offset      : %d\n", ntohs(ipv4_hdr->frag_off));
    printf("\t|-Time to Live         : %d\n", ipv4_hdr->ttl);
    printf("\t|-Protocol             : %d\n", ipv4_hdr->protocol);
    printf("\t|-Header Checksum      : %d\n", ntohs(ipv4_hdr->check));
    printf("\t|-Source IP            : %s\n", src_addr);
    printf("\t|-Destination IP       : %s\n", dst_addr);
}

static void ipv6_print_header(const struct packed_ipv6_hdr *ipv6_hdr) {
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(ipv6_hdr->ip6_src), src_addr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_hdr->ip6_dst), dst_addr, INET6_ADDRSTRLEN);

    printf("IPv6 Header\n");
    printf("   |-Source Address       : %s\n", src_addr);
    printf("   |-Destination Address  : %s\n", dst_addr);
}

static void tcp_print_header(const struct packed_tcp_hdr *tcp_hdr) {
    printf("TCP Header\n");
    printf("\t|-Source Port          : %d\n", ntohs(tcp_hdr->source));
    printf("\t|-Destination Port     : %d\n", ntohs(tcp_hdr->dest));
    printf("\t|-Sequence Number      : %u\n", ntohl(tcp_hdr->seq));
    printf("\t|-Acknowledge Number   : %u\n", ntohl(tcp_hdr->ack_seq));
    printf("\t|-Header Length        : %d DWORDS or %d Bytes\n", packed_tcp_hdr_get_offset(tcp_hdr), packed_tcp_hdr_get_offset(tcp_hdr) * 4);
    printf("\t|-Flags\n");
    printf("\t\t|-FIN              : %d\n", (bool)(tcp_hdr->flag & TH_FIN));
    printf("\t\t|-SYN              : %d\n", (bool)(tcp_hdr->flag & TH_SYN));
    printf("\t\t|-RST              : %d\n", (bool)(tcp_hdr->flag & TH_RST));
    printf("\t\t|-PSH              : %d\n", (bool)(tcp_hdr->flag & TH_PUSH));
    printf("\t\t|-ACK              : %d\n", (bool)(tcp_hdr->flag & TH_ACK));
    printf("\t\t|-URG              : %d\n", (bool)(tcp_hdr->flag & TH_URG));
    printf("\t|-Window               : %d\n", ntohs(tcp_hdr->window));
    printf("\t|-Checksum             : %d\n", ntohs(tcp_hdr->check));
    printf("\t|-Urgent Pointer       : %d\n", tcp_hdr->urg_ptr);
}

static void arp_print_header(const struct packed_etherarp_hdr *ether_arp_hdr) {
    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ether_arp_hdr->arp_spa), sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ether_arp_hdr->arp_tpa), target_ip, INET_ADDRSTRLEN);

    printf("ARP Header\n");
    printf("\t|-Hardware Type        : %u\n", ntohs(ether_arp_hdr->ea_hdr.ar_hrd));
    printf("\t|-Protocol Type        : 0x%04X\n", ntohs(ether_arp_hdr->ea_hdr.ar_pro));
    printf("\t|-Hardware Address Length: %u\n", ether_arp_hdr->ea_hdr.ar_hln);
    printf("\t|-Protocol Address Length: %u\n", ether_arp_hdr->ea_hdr.ar_pln);
    printf("\t|-Operation            : %u\n", ntohs(ether_arp_hdr->ea_hdr.ar_op));
    printf("\t|-Sender MAC Address   : ");
    for (int i = 0; i < ETH_ALEN; i++)
        printf("%02X%c", ether_arp_hdr->arp_sha[i], (i == ETH_ALEN - 1) ? ' ' : ':');
    printf("\n");
    printf("\t|-Sender IP Address    : %s\n", sender_ip);
    printf("\t|-Target MAC Address   : ");
    for (int i = 0; i < ETH_ALEN; i++)
        printf("%02X%c", ether_arp_hdr->arp_tha[i], (i == ETH_ALEN - 1) ? ' ' : ':');
    printf("\n");
    printf("\t|-Target IP Address    : %s\n", target_ip);
}

static void icmp4_print_header(const struct packed_icmp4_hdr *icmp4) {
    printf("ICMP Header\n");
    printf("\t|-Type                 : %d\n", icmp4->type);
    printf("\t|-Code                 : %d\n", icmp4->code);
    printf("\t|-Checksum             : %d\n", ntohs(icmp4->checksum));
    printf("\t|-Identification       : %d\n", ntohs(icmp4->id));
    printf("\t|-Sequence Number      : %d\n", ntohs(icmp4->sequence));
}

static void icmp6_print_header(const struct packed_icmp6_hdr *icmp6) {
    printf("ICMPv6 Header\n");
    printf("\t|-Type                 : %d\n", icmp6->icmp6_type);
    printf("\t|-Code                 : %d\n", icmp6->icmp6_code);
    printf("\t|-Checksum             : %d\n", ntohs(icmp6->icmp6_cksum));
    printf("\t|-Reserved             : %u\n", ntohl(icmp6->icmp6_un_data32[0]));
}

static bool icmp6_process(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len) {
    char *buffer = (char *)xsk_umem__get_data(xsk->umem->buffer, addr);

    if (len < (sizeof(struct packed_eth_hdr) + sizeof(struct packed_ipv6_hdr) + sizeof(struct packed_icmp6_hdr))) {
        return false;
    }

    struct packed_eth_hdr *eth_hdr = (struct packed_eth_hdr *)buffer;
    struct packed_ipv6_hdr *ipv6_hdr = (struct packed_ipv6_hdr *)(eth_hdr + 1);
    struct packed_icmp6_hdr *icmp6_hdr = (struct packed_icmp6_hdr *)(ipv6_hdr + 1);

    if (ntohs(eth_hdr->h_proto) != ETH_P_IPV6 || ipv6_hdr->ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6 || icmp6_hdr->icmp6_type != ICMP6_ECHO_REQUEST) {
        return false;
    }

    printf("ICMP6 <<<<<<<<\n");
    ethernet_print_header(eth_hdr);
    ipv6_print_header(ipv6_hdr);
    icmp6_print_header(icmp6_hdr);

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
    uint16_t checksum = calc_internet_cksum((uint8_t *)icmp6_hdr, len - sizeof(struct packed_eth_hdr) - sizeof(struct packed_ipv6_hdr));
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
    ethernet_print_header(eth_hdr);
    ipv6_print_header(ipv6_hdr);
    icmp6_print_header(icmp6_hdr);

    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
    tx_desc->addr = addr;
    tx_desc->len = len;
    tx_desc->options = 0;
    xsk_ring_prod__submit(&xsk->tx, 1);
    xsk->outstanding_tx++;

    return true;
}

static bool icmp4_process(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len) {
    char *buffer = (char *)xsk_umem__get_data(xsk->umem->buffer, addr);

    if (len < (sizeof(struct packed_eth_hdr) + sizeof(struct packed_ipv4_hdr) + sizeof(struct packed_icmp4_hdr))) {
        return false;
    }

    struct packed_eth_hdr *eth_hdr = (struct packed_eth_hdr *)buffer;
    struct packed_ipv4_hdr *ipv4_hdr = (struct packed_ipv4_hdr *)(eth_hdr + 1);
    struct packed_icmp4_hdr *icmpv4_hdr = (struct packed_icmp4_hdr *)(ipv4_hdr + 1);

    int fail_1 = eth_hdr->h_proto != ntohs(ETH_P_IP);
    int fail_2 = ipv4_hdr->protocol != IPPROTO_ICMP;
    int fail_3 = icmpv4_hdr->type != ICMP_ECHO;
    int fail_4 = icmpv4_hdr->code != 0;

    if (fail_1 || fail_2 || fail_3 || fail_4) {
        return false;
    }

    printf("ICMP4 <<<<<<<<\n");
    ethernet_print_header(eth_hdr);
    ipv4_print_header(ipv4_hdr);
    icmp4_print_header(icmpv4_hdr);

    uint16_t expected_cksum = icmpv4_hdr->checksum;
    uint32_t calculated_len = len - sizeof(struct packed_eth_hdr) - sizeof(struct packed_ipv4_hdr);
    uint32_t calculated_len2 = ntohs(ipv4_hdr->tot_len) - sizeof(struct packed_ipv4_hdr);

    // Validate checksum
    {
        if (calculated_len != calculated_len2) {
            printf("ipv4_hdr->tot_len %hu calculated_len %d calculated_len2 %d\n", ntohs(ipv4_hdr->tot_len), calculated_len, calculated_len2);
            assert(false);
        }
        icmpv4_hdr->checksum = 0;
        uint16_t calculated_cksum = calc_internet_cksum((uint8_t *)icmpv4_hdr, calculated_len);
        if (expected_cksum != calculated_cksum) {
            printf("expected_checksum 0x%x calculated 0x%x\n", expected_cksum, calculated_cksum);
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
    uint16_t checksum = calc_internet_cksum((uint8_t *)icmpv4_hdr, calculated_len);
    icmpv4_hdr->checksum = checksum;

    unsigned int tx_idx = 0;
    unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
    if (ret != 1) {
        printf("ICMP4 cannot send reply\n");
        return false;
    }

    printf("ICMP4 (%d) >>>>>>>>\n", tx_idx);
    ethernet_print_header(eth_hdr);
    ipv4_print_header(ipv4_hdr);
    icmp4_print_header(icmpv4_hdr);

    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
    tx_desc->addr = addr;
    tx_desc->len = len;
    tx_desc->options = 0;
    xsk_ring_prod__submit(&xsk->tx, 1);
    xsk->outstanding_tx++;

    return true;
}

static bool arp_process(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len) {
    char *pkt = (char *)xsk_umem__get_data(xsk->umem->buffer, addr);

    if (len < (sizeof(struct packed_eth_hdr) + sizeof(struct packed_etherarp_hdr))) {
        return false;
    }

    struct packed_eth_hdr *eth_hdr = (struct packed_eth_hdr *)pkt;
    struct packed_etherarp_hdr *arp_hdr = (struct packed_etherarp_hdr *)(eth_hdr + 1);

    if (eth_hdr->h_proto != htons(ETH_P_ARP)) {
        return false;
    }

    static_assert(sizeof(unsigned short) == 2, "helo");
    static_assert(sizeof(uint16_t) == 2, "helo");

    printf("ARP <<<<<<\n");
    ethernet_print_header(eth_hdr);
    arp_print_header(arp_hdr);

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
    const char *our_MAC_address = "\xca\x88\x4f\xae\xd1\x61";
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
    ethernet_print_header(eth_hdr);
    arp_print_header(arp_hdr);

    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
    tx_desc->addr = addr;
    tx_desc->len = len;
    tx_desc->options = 0;
    xsk_ring_prod__submit(&xsk->tx, 1);
    xsk->outstanding_tx++;

    return true;
}
