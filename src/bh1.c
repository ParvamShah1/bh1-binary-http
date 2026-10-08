/*
 * bh1.c - BH/1 framing, header-block codec and frame tracer.
 * Author: Parvam Shah
 */
#include "bh1.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

FILE *bh1_trace = NULL;

static const char *const static_names[BH1_N_COUNT] = {
    [BH1_N_STATUS]         = ":status",
    [BH1_N_METHOD]         = ":method",
    [BH1_N_PATH]           = ":path",
    [BH1_N_HOST]           = "host",
    [BH1_N_ACCEPT]         = "accept",
    [BH1_N_USER_AGENT]     = "user-agent",
    [BH1_N_CONTENT_LENGTH] = "content-length",
    [BH1_N_CONTENT_TYPE]   = "content-type",
    [BH1_N_DATE]           = "date",
    [BH1_N_SERVER]         = "server",
    [BH1_N_ALLOW]          = "allow",
};

/* ---- tracing ---------------------------------------------------------- */

/* Hexdump two byte ranges as if they were one (frame header + payload). */
static void hexdump(char dir, const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    const size_t limit = 256;
    size_t total = an + bn;
    size_t show = total < limit ? total : limit;

    for (size_t off = 0; off < show; off += 16) {
        char ascii[17];
        size_t n = 0;

        fprintf(bh1_trace, "%c   %04zx ", dir, off);
        for (size_t i = 0; i < 16; i++) {
            if (i == 8)
                fputc(' ', bh1_trace);
            if (off + i < show) {
                uint8_t c = off + i < an ? a[off + i] : b[off + i - an];
                fprintf(bh1_trace, " %02x", c);
                ascii[n++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
            } else {
                fputs("   ", bh1_trace);
            }
        }
        ascii[n] = '\0';
        fprintf(bh1_trace, "  |%s|\n", ascii);
    }
    if (show < total)
        fprintf(bh1_trace, "%c   ... %zu more bytes\n", dir, total - show);
}

void bh1_trace_bytes(char dir, const char *what, const uint8_t *p, size_t n)
{
    if (!bh1_trace)
        return;
    flockfile(bh1_trace);
    fprintf(bh1_trace, "%c %s (%zu bytes)\n", dir, what, n);
    hexdump(dir, p, n, NULL, 0);
    funlockfile(bh1_trace);
}

static void trace_frame(char dir, const uint8_t hdr[BH1_HEADER_LEN], const struct bh1_frame *f,
                        const uint8_t *payload)
{
    const char *name = f->type == BH1_HEADERS ? "HEADERS" : f->type == BH1_DATA ? "DATA" : "UNKNOWN";

    flockfile(bh1_trace);
    fprintf(bh1_trace, "%c %s frame: type=0x%02x flags=0x%02x%s len=%u stream=%u\n", dir, name,
            f->type, f->flags, (f->flags & BH1_FIN) ? " [FIN]" : "", (unsigned)f->length,
            (unsigned)f->stream);
    hexdump(dir, hdr, BH1_HEADER_LEN, payload, f->length);
    funlockfile(bh1_trace);
}

/* ---- byte I/O --------------------------------------------------------- */

int bh1_read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;

    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return got == 0 ? 0 : -1;
        got += (size_t)r;
    }
    return 1;
}

int bh1_write_full(int fd, const void *buf, size_t n)
{
    size_t done = 0;

    while (done < n) {
        ssize_t w = write(fd, (const char *)buf + done, n - done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t)w;
    }
    return 0;
}

/* ---- frames (§3) ------------------------------------------------------ */

int bh1_recv_frame(int fd, struct bh1_frame *f)
{
    uint8_t h[BH1_HEADER_LEN];
    int r = bh1_read_full(fd, h, sizeof h);

    if (r <= 0)
        return r;
    f->type = h[0];
    f->flags = h[1];
    f->length = (uint16_t)(h[2] << 8 | h[3]);
    f->stream = (uint32_t)h[4] << 24 | (uint32_t)h[5] << 16 | (uint32_t)h[6] << 8 | h[7];

    /* The payload is read whatever the type is, so an unknown frame has
     * already been skipped by the time the caller looks at it (§4). */
    if (f->length > 0 && bh1_read_full(fd, f->payload, f->length) != 1)
        return -1;
    if (bh1_trace)
        trace_frame('<', h, f, f->payload);
    return 1;
}

int bh1_send_frame(int fd, uint8_t type, uint8_t flags, uint32_t stream, const void *payload,
                   size_t len)
{
    uint8_t h[BH1_HEADER_LEN];
    struct iovec iov[2], *v = iov;
    int left = len > 0 ? 2 : 1;

    if (len > BH1_MAX_PAYLOAD)
        return -1;
    h[0] = type;
    h[1] = flags;
    h[2] = (uint8_t)(len >> 8);
    h[3] = (uint8_t)len;
    h[4] = (uint8_t)(stream >> 24);
    h[5] = (uint8_t)(stream >> 16);
    h[6] = (uint8_t)(stream >> 8);
    h[7] = (uint8_t)stream;

    if (bh1_trace) {
        struct bh1_frame meta = {.type = type, .flags = flags, .length = (uint16_t)len, .stream = stream};
        trace_frame('>', h, &meta, payload);
    }

    /* Header and payload leave in one write so a small frame is one segment. */
    iov[0].iov_base = h;
    iov[0].iov_len = sizeof h;
    iov[1].iov_base = (void *)(uintptr_t)payload;
    iov[1].iov_len = len;
    while (left > 0) {
        ssize_t w = writev(fd, v, left);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        while (left > 0 && (size_t)w >= v->iov_len) {
            w -= (ssize_t)v->iov_len;
            v++;
            left--;
        }
        if (left > 0) {
            v->iov_base = (char *)v->iov_base + w;
            v->iov_len -= (size_t)w;
        }
    }
    return 0;
}

/* ---- header blocks (§5) ----------------------------------------------- */

void bh1_block_reset(struct bh1_block *b)
{
    b->len = 0;
    b->overflow = 0;
}

void bh1_block_add(struct bh1_block *b, const char *name, const char *value)
{
    size_t nlen = strlen(name), vlen = strlen(value);
    int index = 0;

    for (int i = 1; i < BH1_N_COUNT; i++)
        if (strcmp(name, static_names[i]) == 0)
            index = i;

    size_t need = 1 + (index ? 0 : nlen) + 2 + vlen;
    if ((!index && (nlen == 0 || nlen > 127)) || vlen > 65535 || need > sizeof b->buf - b->len) {
        b->overflow = 1;
        return;
    }

    uint8_t *p = b->buf + b->len;
    if (index) {
        *p++ = (uint8_t)(0x80 | index);
    } else {
        *p++ = (uint8_t)nlen;
        memcpy(p, name, nlen);
        p += nlen;
    }
    *p++ = (uint8_t)(vlen >> 8);
    *p++ = (uint8_t)vlen;
    memcpy(p, value, vlen);
    b->len += need;
}

int bh1_next_field(const uint8_t *p, size_t len, size_t *off, struct bh1_field *f)
{
    size_t i = *off;

    if (i >= len)
        return 0;

    uint8_t first = p[i++];
    if (first & 0x80) {
        int index = first & 0x7f;
        if (index == 0 || index >= BH1_N_COUNT)
            return -1;
        f->index = index;
        f->name = static_names[index];
        f->name_len = strlen(f->name);
    } else {
        size_t nlen = first;
        if (nlen == 0 || len - i < nlen)
            return -1;
        for (size_t k = 0; k < nlen; k++) {
            uint8_t c = p[i + k];
            if (c < 0x21 || c > 0x7e || c == ':' || (c >= 'A' && c <= 'Z'))
                return -1;
        }
        f->index = 0;
        f->name = (const char *)p + i;
        f->name_len = nlen;
        i += nlen;
    }

    if (len - i < 2)
        return -1;
    size_t vlen = (size_t)p[i] << 8 | p[i + 1];
    i += 2;
    if (len - i < vlen)
        return -1;
    for (size_t k = 0; k < vlen; k++) {
        uint8_t c = p[i + k];
        if (c == 0x00 || c == '\r' || c == '\n')
            return -1;
    }
    f->value = (const char *)p + i;
    f->value_len = vlen;

    *off = i + vlen;
    return 1;
}
