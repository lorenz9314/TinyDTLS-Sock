#include "sock_types.h"

#define READER_QUEUE_SIZE 16
#define DEFAULT_PORT 20220

msg_t reader_queue[READER_QUEUE_SIZE], msg;

static gnrc_netreg_entry_t server = GNRC_NETREG_ENTRY_INIT_PID(
        GNRC_NETREG_DEMUX_CTX_ALL, KERNEL_PID_UNDEF);

char server_thread_stack[THREAD_STACKSIZE_MAIN
        + THREAD_EXTRA_STACKSIZE_PRINTF];

static void dtls_event_loop(void *arg)
{
    assert(arg);

    dtls_context_t *ctx = (dtls_context_t *) arg;
    msg_t *msg;

    while(1) {
        msg_receive(msg);
        dtls_read_msg(ctx, msg);
    }
}

static void dtls_read_msg(dtls_context_t *ctx, gnrc_pktsnip_t *msg)
{
    sock_udp_ep_t *sck;
    gnrc_pktsnip_t *tmp;
    ipv6_hdr_t *hdr;
    udp_hdr_t *udp;

    sck = ctx->app;

    tmp = gnrc_pktsnip_search_type(msg, GNRC_NETTYPE_IPV6);
    hdr = (ipv6_hdr_t *) tmp->data;

    tmp = gnrc_pktsnip_search_type(msg, GNRC_NETTYPE_UDP);
    udp = (udp_hdr_t *) tmp->data;

    memcpy(&(sck->remote.addr), &(hdr->src), (sizeof(uint8_t)*16));
    sck->remote.port = byteorder_ntohs(udp->src_port);

    sck->session.size = sizeof(ipv6_addr_t) + sizeof(uint16_t);
    sck->session.port = byteorder_ntohs(udp->src_port);
    sck->session.addr = hdr->src;

    dtls_handle_message(ctx, &sock->session, msg->data, 
}

static int dtls_init(dtls_context_t *ctx)
{
    assert(ctx);

    uint32_t port = (uint32_t) DEFAULT_PORT

    static dtls_handler_t handler = {
        .write = send_to_peer,
        .read  = read_from_peer,
        .event = NULL,
        .get_psk_info = peer_get_psk_info
    };

    if (server.target.pid != KERNEL_PID_UNDEF) {
        DEBUG("Server already running, exiting.\n");
        return -1;
    }

    dtls_init();

    server.target.pid = thread_create(server_thread_stack,
            sizeof(server_thread_stack), THREAD_PRIORITY_MAIN - 1,
            THREAD_CREATE_STACKTEST, dtls_event_loop, NULL,
            "DTLS Sock Server");
    server.demux_ctx = port;

    if (gnrc_netreg_register(GNRC_NETTYPE_UDP, &server)) {
        DEBUG("Netreg registration failed, exiting.\n");
        return -1
    }

    DEBUG("Netreg registration successfull, Using port %" PRIu32 "\n", port);

    dtls_set_log_level(DTLS_LOG_DEBUG);
}

int test_fuction(int i)
{
    return i + 1;
}
