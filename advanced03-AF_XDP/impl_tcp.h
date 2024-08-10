#pragma once

#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "impl_inet.h"

struct pseudo_tcphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
} __attribute__((packed));

enum tcp_state {
    tcp_state_CLOSED = 0,
    // tcp_state_INITIALIZED = 1,
    tcp_state_SYN_SENT = 2,
    tcp_state_LISTENING = 3,
};

/// Everything in this struct is in the host byte order.
struct tcp_state_machine {
    // Ethernet
    const char *ethernet_src_mac;
    const char *ethernet_dst_mac;

    // IPV4
    uint16_t ipv4_id;
    const char *ipv4_our_addr;
    const char *ipv4_their_addr;
    uint32_t ipv4_our_addr_int;
    uint32_t ipv4_their_addr_int;

    // TCP
    uint32_t tcp_sequence_id;
    uint32_t tcp_ack_id;
    uint16_t tcp_our_port;
    uint16_t tcp_their_port;
    // NOTE(hanif) - The only thing that is in BE because its a pain in the ass to convert it.
    char *tcp_options_BE_ptr;
    size_t tcp_options_BE_len;

    // Other
    int tcp_state;
};

static struct tcp_state_machine *tcpsm = NULL;

static int tcpsm_init(             //
    struct tcp_state_machine *self //
) {
    assert(self->tcp_state == tcp_state_CLOSED);
    time_t seconds = time(NULL);

    self->ethernet_dst_mac = NULL;
    static const char *SRC_MAC = "\x02\xFA\xAA\x45\xC9\x6D";
    static const char *DST_MAC = "\xCA\x88\x4F\xAE\xD1\x61";
    self->ethernet_src_mac = SRC_MAC;
    self->ethernet_dst_mac = DST_MAC;

    self->ipv4_our_addr = "10.11.1.2";
    self->ipv4_their_addr = "10.11.1.1";
    assert(inet_pton(AF_INET, self->ipv4_our_addr, &self->ipv4_our_addr_int) == 1);
    assert(inet_pton(AF_INET, self->ipv4_their_addr, &self->ipv4_their_addr_int) == 1);
    self->ipv4_our_addr_int = ntohl(self->ipv4_our_addr_int);
    self->ipv4_their_addr_int = ntohl(self->ipv4_their_addr_int);
    self->ipv4_id = seconds % 512;

    self->tcp_sequence_id = seconds % 512;
    self->tcp_ack_id = 0;
    self->tcp_our_port = (seconds % 1024) + 4096;
    self->tcp_their_port = 8080;
    self->tcp_options_BE_ptr = (char *)malloc(4);
    self->tcp_options_BE_len = 4;

    // TCP MSS
    *(self->tcp_options_BE_ptr + 0) = 2;
    *(self->tcp_options_BE_ptr + 1) = 4;
    *(uint16_t *)(self->tcp_options_BE_ptr + 2) = ntohs(0x05B4);

    // self->tcp_state = tcp_state_CLOSED;

    return 0;
}

static int tcpsm_ethernet_create(struct tcp_state_machine *self, struct packed_eth_hdr *res) {
    assert(self->ethernet_src_mac != NULL);
    assert(self->ethernet_dst_mac != NULL);
    assert(sizeof(res->h_dest) == strlen(self->ethernet_src_mac));
    assert(sizeof(res->h_source) == strlen(self->ethernet_dst_mac));

    memcpy(&res->h_source, self->ethernet_src_mac, strlen(self->ethernet_src_mac));
    memcpy(&res->h_dest, self->ethernet_dst_mac, strlen(self->ethernet_dst_mac));
    res->h_proto = htons(ETH_P_IP);

    return 0;
}

static int tcpsm_ipv4_create(       //
    struct tcp_state_machine *self, //
    struct packed_ipv4_hdr *res,    //
    size_t data_len                 //
) {
    res->ihl = 5;
    res->version = 4;
    res->tot_len = htons(sizeof(struct packed_ipv4_hdr) + data_len);
    res->id = htons(self->ipv4_id);
    // NOTE(hanif) - This should be 0 I think?
    res->frag_off = htons(0x4000);
    // res->frag_off = 0;
    res->ttl = 64;
    res->protocol = IPPROTO_TCP;
    res->saddr = htonl(self->ipv4_our_addr_int);
    res->daddr = htonl(self->ipv4_their_addr_int);

    {
        res->check = 0;
        uint16_t cksum = calc_internet_cksum((uint8_t *)res, sizeof(struct packed_ipv4_hdr));
        res->check = cksum;
    }

    self->ipv4_id += 1;

    return 0;
}

static int tcpsm_tcp_create(      //
    struct packed_tcp_hdr *res,   //
    uint32_t ipv4_our_addr_int,   //
    uint32_t ipv4_their_addr_int, //
    // TCP STUFF
    uint16_t tcp_our_port,          //
    uint16_t tcp_their_port,        //
    uint32_t tcp_sequence_id,       //
    uint32_t tcp_ack_id,            //
    uint8_t tcp_flags,              //
    const char *tcp_options_BE_ptr, //
    size_t tcp_options_BE_len,      //
    const char *data_ptr,           //
    size_t data_len                 //
) {
    res->source = htons(tcp_our_port);
    res->dest = htons(tcp_their_port);
    res->seq = htonl(tcp_sequence_id);
    res->ack_seq = htonl(tcp_ack_id);
    res->flag = tcp_flags;
    // assert(tcp_options_len % 4 == 0);
    res->window = ntohs(512);
    uint16_t tcp_options_offset = 0;
    if (tcp_options_BE_ptr != NULL) {
        tcp_options_offset = tcp_options_BE_len / 4;
        memcpy((char *)(res + 1), tcp_options_BE_ptr, tcp_options_BE_len);
    }
    packed_tcp_hdr_set_offset(res, 5 + tcp_options_offset);

    // NOTE(hanif) - This is stupid and slow.
    {
        char *tmp = (char *)malloc(sizeof(struct pseudo_tcphdr) + sizeof(struct packed_tcp_hdr) + tcp_options_offset + data_len);
        struct pseudo_tcphdr *hdr1 = (struct pseudo_tcphdr *)(tmp);
        hdr1->saddr = htonl(ipv4_our_addr_int);
        hdr1->daddr = htonl(ipv4_their_addr_int);
        hdr1->proto = IPPROTO_TCP;
        hdr1->len = htons(sizeof(struct packed_tcp_hdr) + tcp_options_BE_len + data_len);
        memcpy(tmp + sizeof(struct pseudo_tcphdr), (char *)res, sizeof(struct packed_tcp_hdr));
        if (tcp_options_BE_ptr != NULL) {
            memcpy(                                //
                tmp +                              //
                    sizeof(struct pseudo_tcphdr) + //
                    sizeof(struct packed_tcp_hdr), //
                tcp_options_BE_ptr,                //
                tcp_options_BE_len                 //
            );
        }
        if (data_ptr != NULL) {
            memcpy(                                 //
                tmp +                               //
                    sizeof(struct pseudo_tcphdr) +  //
                    sizeof(struct packed_tcp_hdr) + //
                    tcp_options_BE_len,             //
                data_ptr,                           //
                data_len                            //
            );
        }

        res->check = 0;
        uint16_t cksum = calc_internet_cksum( //
            (uint8_t *)tmp,
            sizeof(struct pseudo_tcphdr) +      //
                sizeof(struct packed_tcp_hdr) + //
                tcp_options_BE_len +            //
                data_len                        //
        );
        res->check = cksum;
        free(tmp);
    }

    return 0;
}

// static int tcpsm_write_syn_packet(  //
//     struct tcp_state_machine *self, //
//     char *out_ptr,                  //
//     size_t out_len                  //
// ) {

// }

static bool tcp_init(struct xsk_socket_info *xsk) {
    if (tcpsm != NULL) {
        return 0;
    }

    printf("tcp_init\n");
    tcpsm = (struct tcp_state_machine *)malloc(sizeof(struct tcp_state_machine));
    memset(tcpsm, 0, sizeof(struct tcp_state_machine));
    assert(tcpsm_init(tcpsm) == 0);

    unsigned int tx_idx = 0;
    unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
    if (ret != 1) {
        printf("tcp_init: Unable to reserve XSK producer\n");
        return false;
    }

    const size_t out_len = sizeof(struct packed_eth_hdr) + sizeof(struct packed_ipv4_hdr) + sizeof(struct packed_tcp_hdr) + tcpsm->tcp_options_BE_len;

    struct xdp_desc *xdp_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
    char *out_ptr = (char *)xsk_umem__get_data(xsk->umem->buffer, xdp_desc->addr);
    xdp_desc->len = out_len;
    memset(out_ptr, 0, out_len);

    struct packed_eth_hdr *out_eth_hdr = (struct packed_eth_hdr *)out_ptr;
    struct packed_ipv4_hdr *out_ipv4_hdr = (struct packed_ipv4_hdr *)(out_eth_hdr + 1);
    struct packed_tcp_hdr *out_tcp_hdr = (struct packed_tcp_hdr *)(out_ipv4_hdr + 1);

    assert(tcpsm_ethernet_create(tcpsm, out_eth_hdr) == 0);
    assert(tcpsm_ipv4_create(tcpsm, out_ipv4_hdr, sizeof(struct packed_tcp_hdr) + tcpsm->tcp_options_BE_len) == 0);
    assert(tcpsm_tcp_create(               //
               out_tcp_hdr,                //
               tcpsm->ipv4_our_addr_int,   //
               tcpsm->ipv4_their_addr_int, //
               tcpsm->tcp_our_port,        //
               tcpsm->tcp_their_port,      //
               tcpsm->tcp_sequence_id,     //
               tcpsm->tcp_ack_id,          //
               TH_SYN,                     //
               tcpsm->tcp_options_BE_ptr,  //
               tcpsm->tcp_options_BE_len,  //
               NULL,                       //
               0                           //
               ) == 0);
    tcpsm->tcp_state = tcp_state_SYN_SENT;

    printf("TCP SYN >>>>>>>>\n");
    ethernet_print_header(out_eth_hdr);
    ipv4_print_header(out_ipv4_hdr);
    tcp_print_header(out_tcp_hdr);

    xsk_ring_prod__submit(&xsk->tx, 1);
    xsk->outstanding_tx++;
    complete_tx(xsk);
    return true;
}

static bool tcp_process(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len) {
    const char *in_buffer = (char *)xsk_umem__get_data(xsk->umem->buffer, addr);

    if (len < (sizeof(struct packed_eth_hdr) + sizeof(struct packed_ipv4_hdr) + sizeof(struct packed_tcp_hdr))) {
        return false;
    }

    const struct packed_eth_hdr *in_eth_hdr = (struct packed_eth_hdr *)in_buffer;
    const struct packed_ipv4_hdr *in_ipv4_hdr = (struct packed_ipv4_hdr *)(in_eth_hdr + 1);
    const struct packed_tcp_hdr *in_tcp_hdr = (struct packed_tcp_hdr *)(in_ipv4_hdr + 1);

    if (in_eth_hdr->h_proto != htons(ETH_P_IP)) {
        return false;
    }

    if (in_ipv4_hdr->protocol != IPPROTO_TCP) {
        return false;
    }

    printf("TCP <<<<<<<<\n");
    ethernet_print_header(in_eth_hdr);
    ipv4_print_header(in_ipv4_hdr);
    tcp_print_header(in_tcp_hdr);

    const int tcp_data_len = packed_tcp_hdr_get_data_len(in_ipv4_hdr, in_tcp_hdr);
    printf("tcp_data_len:%d\n", tcp_data_len);
    assert(tcp_data_len >= 0);

    if (in_tcp_hdr->flag == (TH_SYN | TH_ACK)) {
        if (tcpsm->tcp_state != tcp_state_SYN_SENT) {
            printf("DUPLICATE [SYN, ACK] <<<<<<<<\n");
            return false;
        }

        unsigned int tx_idx = 0;
        unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
        if (ret != 1) {
            printf("tcp_process: Unable to reserve XSK producer\n");
            return false;
        }

        const size_t payload_len = sizeof(struct packed_eth_hdr) + sizeof(struct packed_ipv4_hdr) + sizeof(struct packed_tcp_hdr);
        struct xdp_desc *xdp_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
        char *out_buffer = (char *)xsk_umem__get_data(xsk->umem->buffer, xdp_desc->addr);
        xdp_desc->len = payload_len;
        memset(out_buffer, 0, payload_len);

        struct packed_eth_hdr *out_eth_hdr = (struct packed_eth_hdr *)out_buffer;
        struct packed_ipv4_hdr *out_ipv4_hdr = (struct packed_ipv4_hdr *)(out_eth_hdr + 1);
        struct packed_tcp_hdr *out_tcp_hdr = (struct packed_tcp_hdr *)(out_ipv4_hdr + 1);

        // When receiving [SYN,ACK], it should only count for 1 SEQ, so make sure that is true.
        // printf("tcpsm->tcp_sequence_id:%u\ntcpsm->tcp_ack_id:%u\n", //
        //        tcpsm->tcp_sequence_id,                              //
        //        tcpsm->tcp_ack_id                                    //
        // );

        assert(tcp_data_len == 0);
        assert(tcpsm->tcp_sequence_id + 1 == ntohl(in_tcp_hdr->ack_seq));
        tcpsm->tcp_sequence_id = tcpsm->tcp_sequence_id + 1;
        tcpsm->tcp_ack_id = ntohl(in_tcp_hdr->seq) + 1;

        assert(tcpsm_ethernet_create(tcpsm, out_eth_hdr) == 0);
        assert(tcpsm_ipv4_create(tcpsm, out_ipv4_hdr, sizeof(struct packed_tcp_hdr)) == 0);
        assert(tcpsm_tcp_create(               //
                   out_tcp_hdr,                //
                   tcpsm->ipv4_our_addr_int,   //
                   tcpsm->ipv4_their_addr_int, //
                   tcpsm->tcp_our_port,        //
                   tcpsm->tcp_their_port,      //
                   tcpsm->tcp_sequence_id,     //
                   tcpsm->tcp_ack_id,          //
                   TH_ACK,
                   NULL, //
                   0,    //
                   NULL, //
                   0     //
                   ) == 0);
        tcpsm->tcp_state = tcp_state_LISTENING;

        printf("TCP >>>>>>>>>\n");
        ethernet_print_header(out_eth_hdr);
        ipv4_print_header(out_ipv4_hdr);
        tcp_print_header(out_tcp_hdr);

        xsk_ring_prod__submit(&xsk->tx, 1);
        xsk->outstanding_tx++;

    } else if (in_tcp_hdr->flag == (TH_PUSH | TH_ACK)) {
        if (tcpsm->tcp_state != tcp_state_LISTENING) {
            printf("DUPLICATE [PSH, ACK] <<<<<<<<\n");
            return false;
        }

        // TODO(hanif): Check what range of SEQ + LEN it is

        unsigned int tx_idx = 0;
        unsigned int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
        if (ret != 1) {
            printf("tcp_process: Unable to reserve XSK producer\n");
            return false;
        }

        const size_t payload_len = sizeof(struct packed_eth_hdr) + sizeof(struct packed_ipv4_hdr) + sizeof(struct packed_tcp_hdr);
        struct xdp_desc *xdp_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
        char *out_buffer = (char *)xsk_umem__get_data(xsk->umem->buffer, xdp_desc->addr);
        xdp_desc->len = payload_len;
        memset(out_buffer, 0, payload_len);

        struct packed_eth_hdr *out_eth_hdr = (struct packed_eth_hdr *)out_buffer;
        struct packed_ipv4_hdr *out_ipv4_hdr = (struct packed_ipv4_hdr *)(out_eth_hdr + 1);
        struct packed_tcp_hdr *out_tcp_hdr = (struct packed_tcp_hdr *)(out_ipv4_hdr + 1);

        // assert(tcpsm->tcp_sequence_id + 1 == ntohl(in_tcp_hdr->ack_seq));
        // tcpsm->tcp_sequence_id = tcpsm->tcp_sequence_id + 1;
        tcpsm->tcp_ack_id = ntohl(in_tcp_hdr->seq) + tcp_data_len;

        assert(tcpsm_ethernet_create(tcpsm, out_eth_hdr) == 0);
        assert(tcpsm_ipv4_create(tcpsm, out_ipv4_hdr, sizeof(struct packed_tcp_hdr)) == 0);
        assert(tcpsm_tcp_create(               //
                   out_tcp_hdr,                //
                   tcpsm->ipv4_our_addr_int,   //
                   tcpsm->ipv4_their_addr_int, //
                   tcpsm->tcp_our_port,        //
                   tcpsm->tcp_their_port,      //
                   tcpsm->tcp_sequence_id,     //
                   tcpsm->tcp_ack_id,          //
                   TH_ACK,
                   NULL, //
                   0,    //
                   NULL, //
                   0     //
                   ) == 0);
        // tcpsm->tcp_state = tcp_state_LISTENING;

        printf("TCP >>>>>>>>>\n");
        ethernet_print_header(out_eth_hdr);
        ipv4_print_header(out_ipv4_hdr);
        tcp_print_header(out_tcp_hdr);

        xsk_ring_prod__submit(&xsk->tx, 1);
        xsk->outstanding_tx++;

    } else {
        printf("Uhandled state <<<<<<<<\n");
        return false;
    }

    return true;
}

// static int tcp_fill_buffer(struct packed_ethhdr eth_hdr_v, struct packed_ipv4hdr ipv4_hdr_v, struct packed_tcphdr tcp_hdr_v, char *tcp_options_ptr, size_t tcp_options_len, char *buffer, char *data_ptr, size_t data_len) {
//     if (buffer_init == 0) {
//         buffer_init = 1;
//         time_t seconds = time(NULL);
//         ipv4_id = seconds % 512;
//         tcp_sequence_id = seconds % 512;
//         tcp_sport = (seconds % 1024) + 4096;
//     }

//     // struct packed_ethhdr  *eth_hdr = (struct packed_ethhdr  *)buffer;
//     // struct packed_ipv4hdr  *ipv4_hdr = (struct packed_ipv4hdr  *)(eth_hdr + 1);
//     // struct packed_tcphdr *tcp_hdr = (struct packed_tcphdr *)(ipv4_hdr + 1);
//     // char *tcp_options = (char *)(tcp_hdr + 1);
//     // struct packed_ethhdr  eth_hdr_v;
//     // struct packed_ipv4hdr  ipv4_hdr_v;
//     // struct packed_tcphdr tcp_hdr_v;
//     // char tcp_options_v[4];
//     struct packed_ethhdr *eth_hdr = &eth_hdr_v;
//     struct packed_ipv4hdr *ipv4_hdr = &ipv4_hdr_v;
//     struct packed_tcphdr *tcp_hdr = &tcp_hdr_v;
//     char *tcp_options = tcp_options_ptr;
//     // memset(eth_hdr, 0, sizeof(struct packed_ethhdr ));
//     // memset(ipv4_hdr, 0, sizeof(struct packed_ipv4hdr ));
//     // memset(tcp_hdr, 0, sizeof(struct packed_tcphdr));
//     // memset(tcp_options_v, 0, 4);

//     // assert(sizeof(eth_hdr->h_dest) == strlen(DST_MAC));
//     // assert(sizeof(eth_hdr->h_source) == strlen(SRC_MC));

//     // // ETHERNET TYPE II
//     // memcpy(&eth_hdr->h_dest, DST_MAC, strlen(DST_MAC));
//     // memcpy(&eth_hdr->h_source, SRC_MC, strlen(SRC_MC));
//     // eth_hdr->h_proto = htons(ETH_P_IP);

//     // IPV4
//     uint32_t n_saddr = 0;
//     uint32_t n_daddr = 0;
//     assert(inet_pton(AF_INET, "10.11.1.2", &n_saddr) == 1);
//     assert(inet_pton(AF_INET, "10.11.1.1", &n_daddr) == 1);
//     static_assert(sizeof(struct packed_ipv4hdr) + sizeof(struct packed_tcphdr) == 40, "mismatch");

//     // ipv4_hdr->ihl = 5;
//     // ipv4_hdr->version = 4;
//     // ipv4_hdr->tot_len = htons(44) + data_len;
//     // ipv4_hdr->id = htons(ipv4_id);
//     // ipv4_hdr->frag_off = htons(0x4000);
//     // ipv4_hdr->ttl = 64;
//     // ipv4_hdr->protocol = 6;
//     // ipv4_hdr->saddr = n_saddr;
//     // ipv4_hdr->daddr = n_daddr;

//     // {
//     //   ipv4_hdr->check = 0;
//     //   uint16_t cksum = calc_cksum((uint8_t *)ipv4_hdr, sizeof(struct packed_ipv4hdr ));
//     //   ipv4_hdr->check = cksum;
//     // }

//     // TCP
//     tcp_hdr->th_sport = htons(tcp_sport);
//     tcp_hdr->th_dport = htons(8080);
//     tcp_hdr->th_seq = tcp_sequence_id;
//     tcp_hdr->th_off = 6;
//     tcp_hdr->th_flags = TH_SYN;
//     tcp_hdr->th_win = ntohs(512);

//     // TCP Options
//     *(tcp_options + 0) = 2;
//     *(tcp_options + 1) = 4;
//     *(uint16_t *)(tcp_options + 2) = ntohs(0x05B4);

//     {
//         char *ss = (char *)malloc(sizeof(struct pseudo_tcphdr) + sizeof(struct packed_tcphdr) + 4 + data_len);
//         struct pseudo_tcphdr *hdr1 = (struct pseudo_tcphdr *)(ss);
//         hdr1->saddr = n_saddr;
//         hdr1->daddr = n_daddr;
//         hdr1->proto = ipv4_hdr->protocol;
//         hdr1->len = htons(24);
//         // struct packed_tcphdr *hdr2 = (struct packed_tcphdr *)(hdr1 + 1);
//         memcpy(ss + sizeof(struct pseudo_tcphdr), (char *)tcp_hdr, sizeof(struct packed_tcphdr));
//         memcpy(ss + sizeof(struct pseudo_tcphdr) + sizeof(struct packed_tcphdr), (char *)tcp_options, 4);
//         if (data_ptr != NULL) {
//             memcpy(ss + sizeof(struct pseudo_tcphdr) + sizeof(struct packed_tcphdr) + 4, data_ptr, data_len);
//         }

//         tcp_hdr->check = 0;
//         uint16_t cksum = calc_cksum((uint8_t *)ss, sizeof(struct pseudo_tcphdr) + sizeof(struct packed_tcphdr) + 4 + data_len);
//         tcp_hdr->check = cksum;
//         free(ss);
//     }

//     // the rest of it...

//     printf("TCP >>>>>>>>\n");
//     ethernet_print_header(eth_hdr);
//     ipv4_print_header(ipv4_hdr);
//     tcp_print_header(tcp_hdr);

//     // memcpy to the buffer
//     memcpy(buffer, eth_hdr, sizeof(struct packed_ethhdr));
//     memcpy(buffer + sizeof(struct packed_ethhdr), ipv4_hdr, sizeof(struct packed_ipv4hdr));
//     memcpy(buffer + sizeof(struct packed_ethhdr) + sizeof(struct packed_ipv4hdr), tcp_hdr, sizeof(struct packed_tcphdr));
//     memcpy(buffer + sizeof(struct packed_ethhdr) + sizeof(struct packed_ipv4hdr) + sizeof(struct packed_tcphdr), tcp_options, 4);

//     return 0;
// }
