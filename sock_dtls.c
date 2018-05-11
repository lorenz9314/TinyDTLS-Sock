#include "debug.h"
#include "dtls.h"
#include "dtls_debug.h"

#include "net/gnrc.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/udp.h"

#include "include/sock_types.h"


#define READER_QUEUE_SIZE 16
#define DEFAULT_PORT 20220
#define ENABLE_DEBUG (0)

static int dtls_setup(dtls_context_t *ctx);
static void dtls_read_msg(dtls_context_t *ctx, gnrc_pktsnip_t *msg);

msg_t reader_queue[READER_QUEUE_SIZE], msg;

static gnrc_netreg_entry_t server = GNRC_NETREG_ENTRY_INIT_PID(
        GNRC_NETREG_DEMUX_CTX_ALL, KERNEL_PID_UNDEF);

char server_thread_stack[THREAD_STACKSIZE_MAIN
        + THREAD_EXTRA_STACKSIZE_PRINTF];

void *dtls_event_loop(void *arg)
{
    assert(arg);

    dtls_context_t *ctx = (dtls_context_t *) arg;
    msg_t msg;

    while(1) {
        msg_receive(&msg);
        dtls_read_msg(ctx, (gnrc_pktsnip_t *) msg.content.ptr);
    }

    // dtls_free_context(ctx); most likely dead code...
}

static void dtls_read_msg(dtls_context_t *ctx, gnrc_pktsnip_t *msg)
{
    sock_udp_t *sck;
    gnrc_pktsnip_t *tmp;
    ipv6_hdr_t *hdr;
    udp_hdr_t *udp;

    sck = (sock_udp_t *) ctx->app;

    tmp = gnrc_pktsnip_search_type(msg, GNRC_NETTYPE_IPV6);
    hdr = (ipv6_hdr_t *) tmp->data;

    tmp = gnrc_pktsnip_search_type(msg, GNRC_NETTYPE_UDP);
    udp = (udp_hdr_t *) tmp->data;

    memcpy(&(sck->remote.addr), &(hdr->src), (sizeof(uint8_t)*16));
    sck->remote.port = byteorder_ntohs(udp->src_port);

    sck->session.size = sizeof(ipv6_addr_t) + sizeof(uint16_t);
    sck->session.port = byteorder_ntohs(udp->src_port);
    sck->session.addr = hdr->src;

    dtls_handle_message(ctx, &sck->session, msg->data,
            (unsigned int) msg->size);
}

void test_function(void)
{
    dtls_setup(NULL);
}

static int dtls_setup(dtls_context_t *ctx)
{
    assert(ctx);

    uint32_t port = (uint32_t) DEFAULT_PORT;

    static dtls_handler_t handler = {
        .write = NULL, // send_to_peer,
        .read  = NULL, // read_from_peer,
        .event = NULL,
        .get_psk_info = NULL // peer_get_psk_info
    };

    (void) handler;
    (void) ctx;

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
        return -1;
    }

    DEBUG("Netreg registration successfull, Using port %" PRIu32 "\n", port);

    dtls_set_log_level(DTLS_LOG_DEBUG);

    return 0;
}

int sock_udp_create(sock_udp_t *sock, const sock_udp_ep_t *local,
        const sock_udp_ep_t *remote, uint16_t flags)
{
    (void) sock;
    (void) local;
    (void) remote;
    (void) flags;
    return 0;
}

void sock_udp_close(sock_udp_t *sock)
{
    if (server.target.pid == KERNEL_PID_UNDEF) {
        DEBUG("Server not running, exiting.\n");
    }

    dtls_free_context(sock->ctx);

    gnrc_netreg_unregister(GNRC_NETTYPE_UDP, &server);
    server.target.pid = KERNEL_PID_UNDEF;

    DEBUG("Stopped server.\n");
}


int sock_udp_get_local(sock_udp_t *sock, sock_udp_ep_t *ep)
{
    assert(sock && ep);

    if (sock->local.family == AF_UNSPEC) {
        return -EADDRNOTAVAIL;
    }

    memcpy(ep, &sock->local, sizeof(sock_udp_ep_t));

	return 0;
}

int sock_udp_get_remote(sock_udp_t *sock, sock_udp_ep_t *ep)
{
    assert(sock && ep);

    if (sock->remote.family == AF_UNSPEC) {
        return -ENOTCONN;
    }

    memcpy(ep, &sock->remote, sizeof(sock_udp_ep_t));

	return 0;
}

ssize_t sock_udp_recv(sock_udp_t *sock, void *data, size_t max_len,
       	                           uint32_t timeout, sock_udp_ep_t *remote)
{
    (void) sock;
    (void) data;
    (void) max_len;
    (void) timeout;
    (void) remote;

    return 0;
}

ssize_t sock_udp_send(sock_udp_t *sock, const void *data, size_t len,
		                        const sock_udp_ep_t *remote)
{
    (void) sock;
    (void) data;
    (void) len;
    (void) remote;
    return 0;
}


int test_fuction(int i)
{
    return i + 1;
}
