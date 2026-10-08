/*
 * bcurl.c - BH/1 client.
 * Author: Parvam Shah
 *
 *   bcurl [-v] [-I] [-i] URL...
 *
 * URL is host[:port][/path]. Consecutive URLs on the same host:port share
 * one connection. Exit status: 0 ok, 22 a response was 4xx/5xx,
 * 7 could not connect, 8 the peer broke the protocol, 2 usage.
 */
#include "bh1.h"

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define USER_AGENT   "bcurl/1.0"
#define DEFAULT_PORT "9000"

enum { EXIT_OK = 0, EXIT_USAGE = 2, EXIT_CONNECT = 7, EXIT_PROTOCOL = 8, EXIT_HTTP = 22 };

struct url {
    char        authority[300]; /* host[:port] exactly as typed, sent as "host" */
    char        host[256];
    char        port[16];
    const char *path;
};

static int opt_head, opt_show;

static struct bh1_frame frame;
static struct bh1_block block;

static int parse_url(const char *arg, struct url *u)
{
    const char *p = strncmp(arg, "bh1://", 6) == 0 ? arg + 6 : arg;
    const char *slash = strchr(p, '/');
    size_t alen = slash ? (size_t)(slash - p) : strlen(p);
    const char *host = u->authority, *host_end, *port;

    if (alen == 0 || alen >= sizeof u->authority)
        return -1;
    memcpy(u->authority, p, alen);
    u->authority[alen] = '\0';
    u->path = slash ? slash : "/";

    if (*host == '[') { /* [v6-literal]:port */
        host++;
        host_end = strchr(host, ']');
        if (!host_end || (host_end[1] != '\0' && host_end[1] != ':'))
            return -1;
        port = host_end[1] == ':' ? host_end + 2 : NULL;
    } else {
        host_end = strrchr(host, ':');
        port = host_end ? host_end + 1 : NULL;
        if (!host_end)
            host_end = host + strlen(host);
    }
    if (host_end == host || (size_t)(host_end - host) >= sizeof u->host)
        return -1;
    memcpy(u->host, host, (size_t)(host_end - host));
    u->host[host_end - host] = '\0';
    if (port && (*port == '\0' || strlen(port) >= sizeof u->port))
        return -1;
    strcpy(u->port, port ? port : DEFAULT_PORT);
    return 0;
}

static int dial(const struct url *u)
{
    struct addrinfo hints, *res, *ai;
    int fd = -1, on = 1, err;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(u->host, u->port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "bcurl: %s: %s\n", u->authority, gai_strerror(err));
        return -1;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "bcurl: cannot connect to %s\n", u->authority);
        return -1;
    }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);

    bh1_trace_bytes('>', "PREFACE", (const uint8_t *)BH1_PREFACE, BH1_PREFACE_LEN);
    if (bh1_write_full(fd, BH1_PREFACE, BH1_PREFACE_LEN) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int protocol_error(const char *what)
{
    fprintf(stderr, "bcurl: protocol error: %s\n", what);
    return EXIT_PROTOCOL;
}

/* Parse a response header block. Returns the status, or -1 if malformed. */
static int read_head(const struct bh1_frame *fr, long long *content_length)
{
    struct bh1_field f;
    size_t off = 0;
    int r, status = -1, first = 1;

    while ((r = bh1_next_field(fr->payload, fr->length, &off, &f)) == 1) {
        if (first) {
            if (f.index != BH1_N_STATUS || f.value_len != 3)
                return -1;
            status = 0;
            for (int i = 0; i < 3; i++) {
                if (f.value[i] < '0' || f.value[i] > '9')
                    return -1;
                status = status * 10 + (f.value[i] - '0');
            }
            if (opt_show)
                printf("BH/1 %d\n", status);
            first = 0;
            continue;
        }
        if (f.name[0] == ':')
            return -1; /* only one pseudo-field in a response */
        if (f.index == BH1_N_CONTENT_LENGTH) {
            long long n = 0;
            if (f.value_len == 0 || f.value_len > 18)
                return -1;
            for (size_t i = 0; i < f.value_len; i++) {
                if (f.value[i] < '0' || f.value[i] > '9')
                    return -1;
                n = n * 10 + (f.value[i] - '0');
            }
            *content_length = n;
        }
        if (opt_show)
            printf("%.*s: %.*s\n", (int)f.name_len, f.name, (int)f.value_len, f.value);
    }
    if (r < 0 || first)
        return -1;
    if (opt_show)
        putchar('\n');
    return status;
}

/* One request/response exchange. Returns an EXIT_* code. */
static int fetch(int fd, uint32_t stream, const struct url *u)
{
    int status = -1;
    long long content_length = -1, received = 0;

    bh1_block_reset(&block);
    bh1_block_add(&block, ":method", opt_head ? "HEAD" : "GET");
    bh1_block_add(&block, ":path", u->path);
    bh1_block_add(&block, "host", u->authority);
    bh1_block_add(&block, "accept", "*/*");
    bh1_block_add(&block, "user-agent", USER_AGENT);
    if (block.overflow) {
        fprintf(stderr, "bcurl: URL too long\n");
        return EXIT_USAGE;
    }
    if (bh1_send_frame(fd, BH1_HEADERS, BH1_FIN, stream, block.buf, block.len) < 0)
        return protocol_error("connection lost while sending the request");

    for (;;) {
        if (bh1_recv_frame(fd, &frame) != 1)
            return protocol_error("connection closed before the response ended");
        if (frame.type != BH1_HEADERS && frame.type != BH1_DATA)
            continue; /* unknown type: already skipped, flags and stream ignored (§4) */
        if (frame.stream != stream)
            return protocol_error("frame on a stream we did not open");

        if (frame.type == BH1_HEADERS) {
            if (status >= 0)
                return protocol_error("second HEADERS frame in one response");
            status = read_head(&frame, &content_length);
            if (status < 0)
                return protocol_error("malformed response header block");
        } else {
            if (status < 0)
                return protocol_error("DATA before HEADERS");
            if (opt_head && frame.length > 0)
                return protocol_error("body in the response to HEAD");
            if (fwrite(frame.payload, 1, frame.length, stdout) != frame.length)
                return EXIT_PROTOCOL;
            received += frame.length;
        }
        if (frame.flags & BH1_FIN)
            break;
    }
    fflush(stdout);

    if (!opt_head && content_length >= 0 && received != content_length)
        return protocol_error("body length does not match content-length");
    if (status >= 400) {
        fprintf(stderr, "bcurl: %s%s: status %d\n", u->authority, u->path, status);
        return EXIT_HTTP;
    }
    return EXIT_OK;
}

static int usage(void)
{
    fprintf(stderr, "usage: bcurl [-v] [-I] [-i] URL...\n"
                    "  -v  hexdump every frame to stderr\n"
                    "  -I  send HEAD and print the response fields\n"
                    "  -i  print the response fields before the body\n"
                    "URL is host[:port][/path]; the default port is " DEFAULT_PORT ".\n");
    return EXIT_USAGE;
}

int main(int argc, char **argv)
{
    int opt, fd = -1, result = EXIT_OK;
    uint32_t stream = 0;
    char connected_to[300] = "";

    while ((opt = getopt(argc, argv, "vIi")) != -1) {
        if (opt == 'v')
            bh1_trace = stderr;
        else if (opt == 'I')
            opt_head = opt_show = 1;
        else if (opt == 'i')
            opt_show = 1;
        else
            return usage();
    }
    if (optind == argc)
        return usage();
    signal(SIGPIPE, SIG_IGN);

    for (int i = optind; i < argc; i++) {
        struct url u;
        int rc;

        if (parse_url(argv[i], &u) < 0) {
            fprintf(stderr, "bcurl: bad URL: %s\n", argv[i]);
            return EXIT_USAGE;
        }
        if (fd < 0 || strcmp(connected_to, u.authority) != 0) {
            if (fd >= 0)
                close(fd);
            fd = dial(&u);
            if (fd < 0)
                return EXIT_CONNECT;
            strcpy(connected_to, u.authority);
            stream = 0;
        }
        rc = fetch(fd, ++stream, &u);
        if (rc == EXIT_HTTP)
            result = EXIT_HTTP; /* the connection is still good: carry on */
        else if (rc != EXIT_OK)
            return rc;
    }
    close(fd);
    return result;
}
