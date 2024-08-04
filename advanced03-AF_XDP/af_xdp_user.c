#include "impl_tcp.h"

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

    {{"help", no_argument, NULL, 'h'}, "Show help", false},

    {{"dev", required_argument, NULL, 'd'}, "Operate on device <ifname>", "<ifname>", true},

    {{"skb-mode", no_argument, NULL, 'S'}, "Install XDP program in SKB (AKA generic) mode"},

    {{"native-mode", no_argument, NULL, 'N'}, "Install XDP program in native mode"},

    {{"auto-mode", no_argument, NULL, 'A'}, "Auto-detect SKB or native mode"},

    {{"force", no_argument, NULL, 'F'}, "Force install, replacing existing program on interface"},

    {{"copy", no_argument, NULL, 'c'}, "Force copy mode"},

    {{"zero-copy", no_argument, NULL, 'z'}, "Force zero-copy mode"},

    {{"queue", required_argument, NULL, 'Q'}, "Configure interface receive queue for AF_XDP, default=0"},

    {{"poll-mode", no_argument, NULL, 'p'}, "Use the poll() API waiting for packets to arrive"},

    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},

    {{"filename", required_argument, NULL, 1}, "Load program from <file>", "<file>"},

    {{"progname", required_argument, NULL, 2}, "Load program from function <name> in the ELF file", "<name>"},

    {{0, 0, NULL, 0}, NULL, false}};

static bool global_exit;

static bool handle_recv(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len) {
    printf("handle_recv\n");
    bool is_ok = false;
    is_ok = icmp6_process(xsk, addr, len);
    if (is_ok) {
        return true;
    }

    is_ok = icmp4_process(xsk, addr, len);
    if (is_ok) {
        return true;
    }

    is_ok = arp_process(xsk, addr, len);
    if (is_ok) {
        return true;
    }

    // is_ok = tcp_process(xsk, addr, len);
    // if (is_ok) {
    //     return true;
    // }

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
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = xsk_alloc_umem_frame(xsk);

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

static void exit_application(int signal) {
    int err;

    cfg.unload_all = true;
    err = do_unload(&cfg);
    if (err) {
        fprintf(stderr, "Couldn't detach XDP program on iface '%s' : (%d)\n", cfg.ifname, err);
    }

    signal = signal;
    global_exit = true;
}

int main(int argc, char **argv) {
    // int ret;
    void *packet_buffer;
    uint64_t packet_buffer_size;
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct xsk_umem_info *umem;
    struct xsk_socket_info *xsk_socket;
    // pthread_t stats_poll_thread;
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
            fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n", cfg.ifname, errmsg, err);
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
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&packet_buffer, getpagesize(), /* PAGE_SIZE aligned */
                       packet_buffer_size)) {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n", strerror(errno));
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
        fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    main_loop(&cfg, xsk_socket);

    /* Cleanup */
    xsk_socket__delete(xsk_socket->xsk);
    xsk_umem__delete(umem->umem);

    return EXIT_OK;
}
