/*
 * bserve.c - BH/1 static file server.
 * Author: Parvam Shah
 *
 *   bserve [-v] [-g] ROOT PORT
 *
 * One detached thread per connection; each thread answers its requests
 * strictly in order (SPEC.md §1).
 */
#include "bh1.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SERVER_NAME "bserve/1.0"

static char   root[PATH_MAX];
static size_t root_len;
static int    opt_grease;

struct conn {
    int              fd;
    uint32_t         rng;
    struct bh1_frame in;
    struct bh1_block out;
    uint8_t          chunk[BH1_DATA_CHUNK];
};

static const char *reason(int status)
{
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    default:  return "Error";
    }
}

static const char *content_type(const char *path)
{
    static const struct {
        const char *ext, *type;
    } types[] = {
        {"html", "text/html; charset=utf-8"}, {"htm", "text/html; charset=utf-8"},
        {"txt", "text/plain; charset=utf-8"}, {"css", "text/css; charset=utf-8"},
        {"js", "text/javascript; charset=utf-8"}, {"json", "application/json"},
        {"png", "image/png"}, {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"},
        {"gif", "image/gif"}, {"svg", "image/svg+xml"}, {"pdf", "application/pdf"},
    };
    const char *slash = strrchr(path, '/');
    const char *dot = strrchr(slash ? slash : path, '.');

    if (dot)
        for (size_t i = 0; i < sizeof types / sizeof types[0]; i++)
            if (strcasecmp(dot + 1, types[i].ext) == 0)
                return types[i].type;
    return "application/octet-stream";
}

static uint32_t next_random(struct conn *c)
{
    c->rng ^= c->rng << 13;
    c->rng ^= c->rng >> 17;
    c->rng ^= c->rng << 5;
    return c->rng;
}

/* -g: send a frame no BH/1 peer knows, with junk flags, so that a client
 * which fails to skip unknown types breaks straight away (§4). */
static int grease(struct conn *c, uint32_t stream)
{
    uint8_t junk[16];
    uint32_t r;

    if (!opt_grease)
        return 0;
    r = next_random(c);
    for (size_t i = 0; i < sizeof junk; i++)
        junk[i] = (uint8_t)next_random(c);
    return bh1_send_frame(c->fd, (uint8_t)(0xE0 | (r & 0x1f)), (uint8_t)(r >> 8),
                          (r & 0x10000) ? stream : 0, junk, (r >> 20) % (sizeof junk + 1));
}

static int send_head(struct conn *c, uint32_t stream, int status, const char *ctype,
                     unsigned long long clen, int fin)
{
    char buf[64];
    time_t now = time(NULL);
    struct tm tm;

    bh1_block_reset(&c->out);
    snprintf(buf, sizeof buf, "%d", status);
    bh1_block_add(&c->out, ":status", buf);
    bh1_block_add(&c->out, "content-type", ctype);
    snprintf(buf, sizeof buf, "%llu", clen);
    bh1_block_add(&c->out, "content-length", buf);
    if (status == 405)
        bh1_block_add(&c->out, "allow", "GET, HEAD");
    gmtime_r(&now, &tm);
    strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    bh1_block_add(&c->out, "date", buf);
    bh1_block_add(&c->out, "server", SERVER_NAME);

    if (grease(c, stream) < 0)
        return -1;
    return bh1_send_frame(c->fd, BH1_HEADERS, fin ? BH1_FIN : 0, stream, c->out.buf, c->out.len);
}

static int send_error(struct conn *c, uint32_t stream, int status, int head)
{
    char body[64];
    int n = snprintf(body, sizeof body, "%d %s\n", status, reason(status));

    if (send_head(c, stream, status, "text/plain; charset=utf-8", (unsigned long long)n, head) < 0)
        return -1;
    if (head)
        return 0;
    return bh1_send_frame(c->fd, BH1_DATA, BH1_FIN, stream, body, (size_t)n);
}

static int hexval(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Drop the ?query and percent-decode. Returns -1 if the path is malformed. */
static int decode_path(const char *in, size_t n, char *out, size_t cap)
{
    size_t o = 0;

    if (n == 0 || in[0] != '/')
        return -1;
    for (size_t i = 0; i < n && in[i] != '?' && in[i] != '#'; i++) {
        char ch = in[i];
        if (ch == '%') {
            int hi = i + 2 < n ? hexval(in[i + 1]) : -1;
            int lo = i + 2 < n ? hexval(in[i + 2]) : -1;
            if (hi < 0 || lo < 0 || (hi == 0 && lo == 0))
                return -1;
            ch = (char)(hi << 4 | lo);
            i += 2;
        }
        if (o + 1 >= cap)
            return -1;
        out[o++] = ch;
    }
    out[o] = '\0';
    return 0;
}

static int inside_root(const char *real)
{
    return strncmp(real, root, root_len) == 0 && (real[root_len] == '/' || real[root_len] == '\0');
}

/* Map a decoded request path to an open file under the root, or -1 (-> 404).
 * realpath() resolves ".." and symlinks, so the prefix check is on the
 * file that would really be opened (§6). */
static int open_target(const char *path, char real[PATH_MAX], struct stat *st)
{
    char full[PATH_MAX];
    int fd;

    if ((size_t)snprintf(full, sizeof full, "%s%s", root, path) >= sizeof full)
        return -1;
    if (!realpath(full, real) || !inside_root(real) || stat(real, st) < 0)
        return -1;
    if (S_ISDIR(st->st_mode)) {
        if ((size_t)snprintf(full, sizeof full, "%s/index.html", real) >= sizeof full)
            return -1;
        if (!realpath(full, real) || !inside_root(real))
            return -1;
    } else if (path[strlen(path) - 1] == '/') {
        return -1; /* "/file.txt/" names nothing; some realpath()s let it through */
    }
    fd = open(real, O_RDONLY);
    if (fd < 0)
        return -1;
    if (fstat(fd, st) < 0 || !S_ISREG(st->st_mode)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int serve_file(struct conn *c, uint32_t stream, const char *path, int head)
{
    char real[PATH_MAX];
    struct stat st;
    int rc = 0;
    int file = open_target(path, real, &st);

    if (file < 0)
        return send_error(c, stream, 404, head);

    off_t left = st.st_size;
    if (send_head(c, stream, 200, content_type(real), (unsigned long long)left, head || left == 0) < 0)
        rc = -1;

    while (rc == 0 && !head && left > 0) {
        size_t want = left < (off_t)sizeof c->chunk ? (size_t)left : sizeof c->chunk;
        ssize_t n = read(file, c->chunk, want);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            rc = -1; /* file shrank under us: the 200 is already sent, so close (§7) */
            break;
        }
        left -= n;
        if (left == 0 && grease(c, stream) < 0)
            rc = -1;
        else if (bh1_send_frame(c->fd, BH1_DATA, left == 0 ? BH1_FIN : 0, stream, c->chunk, (size_t)n) < 0)
            rc = -1;
    }
    close(file);
    return rc;
}

/* Returns 0 to keep the connection, -1 to close it. */
static int handle_request(struct conn *c)
{
    const struct bh1_frame *fr = &c->in;
    struct bh1_field f;
    const char *method = NULL, *path = NULL;
    size_t method_len = 0, path_len = 0, off = 0;
    int r, bad = 0, seen_regular = 0, head;
    char decoded[PATH_MAX];

    if (fr->stream == 0)
        return -1; /* no stream to answer on */

    while ((r = bh1_next_field(fr->payload, fr->length, &off, &f)) == 1) {
        if (f.name[0] != ':') {
            seen_regular = 1;
        } else if (seen_regular) {
            bad = 1;
        } else if (f.index == BH1_N_METHOD && !method) {
            method = f.value;
            method_len = f.value_len;
        } else if (f.index == BH1_N_PATH && !path) {
            path = f.value;
            path_len = f.value_len;
        } else {
            bad = 1; /* duplicate, or :status in a request */
        }
    }
    if (r < 0 || bad || !method || !path || !(fr->flags & BH1_FIN))
        return send_error(c, fr->stream, 400, 0);
    if (decode_path(path, path_len, decoded, sizeof decoded) < 0)
        return send_error(c, fr->stream, 400, 0);

    head = method_len == 4 && memcmp(method, "HEAD", 4) == 0;
    if (!head && !(method_len == 3 && memcmp(method, "GET", 3) == 0))
        return send_error(c, fr->stream, 405, 0);

    return serve_file(c, fr->stream, decoded, head);
}

static void *connection(void *arg)
{
    struct conn *c = arg;
    uint8_t preface[BH1_PREFACE_LEN];

    if (bh1_read_full(c->fd, preface, sizeof preface) == 1 &&
        memcmp(preface, BH1_PREFACE, sizeof preface) == 0) {
        bh1_trace_bytes('<', "PREFACE", preface, sizeof preface);
        while (bh1_recv_frame(c->fd, &c->in) == 1) {
            /* DATA from a client is ignored, and so is every type we
             * don't know: recv_frame has already consumed the payload. */
            if (c->in.type == BH1_HEADERS && handle_request(c) < 0)
                break;
        }
    }
    close(c->fd);
    free(c);
    return NULL;
}

static int listen_on(int port)
{
    int on = 1, off = 0;
    int fd = socket(AF_INET6, SOCK_STREAM, 0);

    if (fd >= 0) {
        struct sockaddr_in6 a6;
        memset(&a6, 0, sizeof a6);
        a6.sin6_family = AF_INET6;
        a6.sin6_addr = in6addr_any;
        a6.sin6_port = htons((uint16_t)port);
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off); /* take IPv4 too */
        if (bind(fd, (struct sockaddr *)&a6, sizeof a6) == 0 && listen(fd, 64) == 0)
            return fd;
        close(fd);
    }

    /* No IPv6 on this host: plain IPv4. */
    struct sockaddr_in a4;
    memset(&a4, 0, sizeof a4);
    a4.sin_family = AF_INET;
    a4.sin_addr.s_addr = htonl(INADDR_ANY);
    a4.sin_port = htons((uint16_t)port);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (bind(fd, (struct sockaddr *)&a4, sizeof a4) < 0 || listen(fd, 64) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int usage(void)
{
    fprintf(stderr, "usage: bserve [-v] [-g] ROOT PORT\n"
                    "  -v  hexdump every frame to stderr\n"
                    "  -g  grease: send an unknown frame type before each response\n");
    return 2;
}

int main(int argc, char **argv)
{
    int opt, port, lfd;
    char *end;
    struct stat st;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;

    while ((opt = getopt(argc, argv, "vg")) != -1) {
        if (opt == 'v')
            bh1_trace = stderr;
        else if (opt == 'g')
            opt_grease = 1;
        else
            return usage();
    }
    if (argc - optind != 2)
        return usage();

    if (!realpath(argv[optind], root) || stat(root, &st) < 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "bserve: %s: not a directory\n", argv[optind]);
        return 1;
    }
    root_len = strcmp(root, "/") == 0 ? 0 : strlen(root);

    port = (int)strtol(argv[optind + 1], &end, 10);
    if (*end != '\0' || end == argv[optind + 1] || port < 0 || port > 65535)
        return usage();

    signal(SIGPIPE, SIG_IGN);
    lfd = listen_on(port);
    if (lfd < 0) {
        perror("bserve: listen");
        return 1;
    }
    if (getsockname(lfd, (struct sockaddr *)&ss, &sl) == 0)
        port = ntohs(ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                                              : ((struct sockaddr_in *)&ss)->sin_port);
    printf("bserve: serving %s on port %d\n", root, port);
    fflush(stdout);

    for (;;) {
        int on = 1;
        pthread_t tid;
        struct conn *c;
        int fd = accept(lfd, NULL, NULL);

        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            perror("bserve: accept");
            return 1;
        }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        c = malloc(sizeof *c);
        if (!c) {
            close(fd);
            continue;
        }
        c->fd = fd;
        c->rng = (uint32_t)time(NULL) ^ ((uint32_t)fd << 16) ^ 0x9e3779b9u;
        if (pthread_create(&tid, NULL, connection, c) != 0) {
            close(fd);
            free(c);
            continue;
        }
        pthread_detach(tid);
    }
}
