/*
 * bh1.h - BH/1 wire format shared by bserve and bcurl.
 * Author: Parvam Shah
 *
 * Section numbers in comments refer to SPEC.md.
 */
#ifndef BH1_H
#define BH1_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* §2 connection preface */
#define BH1_PREFACE     "BH/1\r\n\r\n"
#define BH1_PREFACE_LEN 8

/* §3 frame header: Type(8) Flags(8) Length(16) Stream(32) */
#define BH1_HEADER_LEN  8
#define BH1_MAX_PAYLOAD 65535
#define BH1_DATA_CHUNK  16384 /* largest DATA payload we send */

/* §4 frame types and flags */
#define BH1_HEADERS 0x01
#define BH1_DATA    0x02
#define BH1_FIN     0x01

/* §5 static name table (the wire byte is 0x80 | index) */
enum {
    BH1_N_STATUS = 1,
    BH1_N_METHOD,
    BH1_N_PATH,
    BH1_N_HOST,
    BH1_N_ACCEPT,
    BH1_N_USER_AGENT,
    BH1_N_CONTENT_LENGTH,
    BH1_N_CONTENT_TYPE,
    BH1_N_DATE,
    BH1_N_SERVER,
    BH1_N_ALLOW,
    BH1_N_COUNT
};

struct bh1_frame {
    uint8_t  type;
    uint8_t  flags;
    uint16_t length;
    uint32_t stream;
    uint8_t  payload[BH1_MAX_PAYLOAD];
};

/* One decoded field. name/value point into the payload (or the static table)
 * and are NOT NUL-terminated; index is 0 for a literal name. */
struct bh1_field {
    int         index;
    const char *name;
    size_t      name_len;
    const char *value;
    size_t      value_len;
};

/* A header block being built for sending. */
struct bh1_block {
    uint8_t buf[BH1_MAX_PAYLOAD];
    size_t  len;
    int     overflow;
};

/* When non-NULL, every frame sent or received is hexdumped here. */
extern FILE *bh1_trace;

/* 1 = got n bytes, 0 = EOF before the first byte, -1 = error or EOF midway. */
int bh1_read_full(int fd, void *buf, size_t n);
int bh1_write_full(int fd, const void *buf, size_t n);

/* 1 = frame read, 0 = clean EOF on a frame boundary, -1 = truncated/error. */
int bh1_recv_frame(int fd, struct bh1_frame *f);
int bh1_send_frame(int fd, uint8_t type, uint8_t flags, uint32_t stream,
                   const void *payload, size_t len);

void bh1_block_reset(struct bh1_block *b);
void bh1_block_add(struct bh1_block *b, const char *name, const char *value);

/* Walk a header block: start with *off = 0 and call until it stops returning 1.
 * 1 = field decoded, 0 = end of block, -1 = malformed. */
int bh1_next_field(const uint8_t *p, size_t len, size_t *off, struct bh1_field *f);

void bh1_trace_bytes(char dir, const char *what, const uint8_t *p, size_t n);

#endif
