# BH/1: HTTP semantics in binary frames

**Author:** Parvam Shah · **Status:** version 1, Network Architecture course project

MUST, MUST NOT, SHOULD and MAY have their RFC 2119 meanings. Every multi-byte integer is
**unsigned and big-endian** (network byte order).

## 1. Overview

BH/1 carries HTTP requests and responses (method, path, status, header fields, body) as
length-prefixed binary frames over one TCP connection, instead of as lines of text.

A client connects, sends a fixed preface, then sends requests. Every request gets exactly one
response, and the two are tied together by a **stream ID** chosen by the client. Version 1
is strictly sequential: the server answers requests in the order they arrive and finishes one
response before starting the next. A client MAY pipeline (send several requests without
waiting); the responses still come back in request order. The connection stays open until
one side closes it, which it SHOULD only do between messages.

## 2. Connection preface

The first 8 bytes a client sends MUST be:

```
42 48 2F 31 0D 0A 0D 0A        "BH/1" CR LF CR LF
```

If a server reads anything else, it MUST close the connection and send nothing: the peer is
not speaking BH/1 and would not understand a BH/1 error. The server sends no preface of its
own.

The preface is the version check. It ends in a blank line on purpose: if a BH/1 client is
pointed at an ordinary HTTP/1.1 server by mistake, that server sees a complete (and invalid)
request, answers `400`, and the client fails at once on a bad frame instead of both sides
waiting for more bytes. The `1` changes only for an incompatible revision; compatible
additions use new frame types (§4).

## 3. Frame header

After the preface, each direction is a sequence of **frames**: a fixed 8-byte header, then
exactly `Length` bytes of payload.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+-------------------------------+
|   Type (8)    |   Flags (8)   |          Length (16)          |
+---------------+---------------+-------------------------------+
|                         Stream ID (32)                        |
+---------------------------------------------------------------+
|                   Payload (Length bytes) ...
```

| Offset | Field | Width | Meaning |
|---|---|---|---|
| 0 | Type | 8 bits | What the payload is (§4). |
| 1 | Flags | 8 bits | Booleans. Bits that are not defined MUST be sent as 0 and MUST be ignored when received. |
| 2 | Length | 16 bits | Payload size in bytes, excluding the header: 0 to 65 535. |
| 4 | Stream ID | 32 bits | The request/response this frame belongs to. 0 is reserved for frames about the connection as a whole. |

### Why these fields and widths

* **Fixed size, length at a fixed offset.** A receiver can find the end of *any* frame from
  bytes 2–3 alone, without understanding the type. The skip rule in §4 depends on this.
* **16-bit length.** The largest frame is 64 KiB, so a receiver needs one fixed 64 KiB buffer
  and can never be asked for more. That limit is part of the wire format rather than
  something to negotiate. Bodies of any size are split across DATA frames, so the cost is
  8 bytes of header per 64 KiB (about 0.01 %). A header block has to fit in one frame, which
  caps it at 64 KiB; real header blocks are a few hundred bytes.
* **8-bit type.** Two types are defined; 254 are left for extensions.
* **8-bit flags.** One bit is used. The other seven are free for things like padding or
  compression in a later version.
* **32-bit stream ID.** Version 1 has only one stream active at a time, so the ID is a
  correlation number, and the field that would let a later version interleave streams.
  32 bits means a connection can carry four billion requests without the ID ever being reused.
* **Alignment.** The fields are 1 + 1 + 2 + 4 bytes, each on its natural boundary, and the
  header is exactly 8 bytes. It maps onto a C struct with no padding, and offsets are easy to
  work out by hand in a hexdump.

### Why HTTP/2 chose 24 / 8 / 8 / 1 + 31

HTTP/2's header is 9 bytes: Length (24), Type (8), Flags (8), a reserved bit, Stream ID (31).

* **24-bit length**, but a peer may only send 16 384 bytes unless the receiver raises
  `SETTINGS_MAX_FRAME_SIZE`. The wide field allows 16 MiB frames for bulk transfers; the small
  default stops one big frame from blocking every other stream on a multiplexed connection.
  BH/1 has no SETTINGS frame and no multiplexing, so it puts the limit in the field width
  instead and saves a byte.
* **Length first** in HTTP/2, type first in BH/1. Either works, because both headers are fixed
  size; BH/1 puts the two bytes a receiver dispatches on at the front.
* **31-bit stream ID.** HTTP/2 never reuses a stream ID on a connection, and splits the space
  (odd for the client, even for the server, which needs IDs for push). The top bit is
  reserved, which also keeps the value non-negative in languages without unsigned 32-bit
  integers. BH/1 has no server-initiated streams, so it keeps all 32 bits and a simpler rule.

## 4. Frame types, flags and unknown frames

| Type | Name | Stream ID | Payload |
|---|---|---|---|
| `0x01` | HEADERS | not 0 | One header block (§5). Starts a request or a response. |
| `0x02` | DATA | not 0 | Body bytes. Length MAY be 0. |
| `0x00`, `0x03`–`0xFF` | unassigned | any | See below. `0xE0`–`0xFF` are set aside for experiments and greasing. |

`0x00` is deliberately unassigned, so a run of zero bytes is never a meaningful frame.

One flag is defined: **`0x01` FIN**, "this is the last frame of this message". The other
seven bits are reserved.

**Unknown frame types.**

> A receiver that gets a frame whose type it does not know MUST read and discard exactly
> `Length` bytes of payload and carry on as though the frame had not been sent. It MUST NOT
> treat the frame as an error, and it MUST NOT act on that frame's flags or stream ID.

This is how BH/1 grows. A later minor version can add, for example, a PING or a WINDOW frame,
and a version 1 peer steps over it. The second half of the rule matters as much as the first:
a FIN bit on an unknown frame does *not* end the current message.

Rules that are never exercised stop being true, so a server MAY **grease**: send a frame of a
random type in `0xE0`–`0xFF`, with any flags and payload, at any frame boundary. `bserve -g`
does this before every response and before the last DATA frame of a body.

## 5. Header blocks

The payload of a HEADERS frame is a list of fields, one after another, until the payload
runs out. There is no field count and no terminator.

```
+--------+-----------------------------+----------------+------------------+
| Name 8 | [Name bytes] if literal     | Value length 16 | Value bytes      |
+--------+-----------------------------+----------------+------------------+
```

The first byte says how the name is given:

| First byte | Meaning |
|---|---|
| `1xxxxxxx` (`0x81`–`0x8B`) | **Indexed name.** The low 7 bits are a row of the static table below. No name bytes follow. |
| `0xxxxxxx` (`0x01`–`0x7F`) | **Literal name.** The byte is the name's length (1–127), and that many name bytes follow. |

`0x00`, `0x80` and `0x8C`–`0xFF` (index 0 or past the end of the table) are malformed.

Then comes the value: a 16-bit length (0–65 535) and that many bytes.

**Static name table**

| Index | Wire byte | Name | Index | Wire byte | Name |
|---|---|---|---|---|---|
| 1 | `0x81` | `:status` | 7 | `0x87` | `content-length` |
| 2 | `0x82` | `:method` | 8 | `0x88` | `content-type` |
| 3 | `0x83` | `:path` | 9 | `0x89` | `date` |
| 4 | `0x84` | `host` | 10 | `0x8A` | `server` |
| 5 | `0x85` | `accept` | 11 | `0x8B` | `allow` |
| 6 | `0x86` | `user-agent` | | | |

These are the eleven names `bcurl` and `bserve` send, so ordinary traffic has no literal
names at all: a name costs 1 byte, and a value costs 2 bytes plus its length. A literal name
costs 1 + n bytes. Putting the indexed/literal choice in the top bit means neither form
wastes a byte on a marker. It also leaves room for 116 more table entries.

Rules:

* Literal names MUST be lowercase visible ASCII: bytes `0x21`–`0x7E`, excluding `A`–`Z` and `:`.
* A sender MUST use the index for a name that is in the table.
* Values MUST NOT contain `0x00`, CR or LF. (This keeps every BH/1 message translatable to
  HTTP/1.1 without creating a header-injection hole.)
* Names beginning with `:` are **pseudo-fields**. They can only be sent by index, MUST come
  before every ordinary field, and MUST NOT appear twice.

This is the idea behind HPACK's static table and length-prefixed literals, without its
dynamic table and Huffman coding. Those compress better, but they make each header block
depend on every block before it; BH/1 keeps blocks independent so that one can be decoded,
or rejected, entirely on its own.

## 6. Requests and responses

**Request.** A single HEADERS frame with FIN set, on a non-zero stream ID. Version 1
requests have no body. The block MUST contain `:method` and `:path`. `:path` MUST start with
`/`; it may contain `%XX` escapes and a `?query`, and the server ignores the query. Clients
SHOULD send `host` and SHOULD number streams 1, 2, 3, … on each connection. A server MUST
accept any non-zero stream ID and echo it.

**Response.** On the **same stream ID**: one HEADERS frame whose first field is `:status`
(three ASCII digits), then zero or more DATA frames. The last frame of the response has FIN.
That is the HEADERS frame when there is no body (a HEAD request, an empty file), and
otherwise the final DATA frame, which MAY be empty. A response MUST NOT contain a second
HEADERS frame. Servers SHOULD send `content-length`, and a client that receives one SHOULD
check it against the bytes it actually got. A receiver MUST NOT assume anything about how a
body is divided into DATA frames.

**Methods.** `GET` and `HEAD`. Anything else gets `405`. The response to `HEAD` is the
HEADERS frame a `GET` would produce, with FIN and no DATA.

**Paths.** The server removes the query, percent-decodes the rest, and looks it up under
its document root. A directory is answered with its `index.html`. The server MUST NOT serve
a file that is outside the root once `..` segments and symbolic links are resolved; such a
request gets `404`, the same as a file that does not exist.

## 7. Errors

| Situation | Seen by | What happens |
|---|---|---|
| Preface is wrong | server | Close the connection. No reply. |
| HEADERS on stream 0 | server | Close the connection: there is no stream to reply on. |
| Malformed header block: bad index, zero-length or badly spelled literal name, a field cut off by the end of the payload, NUL/CR/LF in a value | server | `400` on that stream. **The connection stays open.** |
| Missing, repeated or misplaced pseudo-field; `:status` in a request; `:path` not starting with `/`, or with a bad `%` escape | server | `400`, connection stays open. |
| Request HEADERS without FIN | server | `400`, connection stays open. |
| Method is not GET or HEAD | server | `405` with `allow: GET, HEAD`. |
| No such file, or it is outside the root | server | `404`. |
| Unknown frame type | both | Skipped (§4). Never an error. |
| Unknown flag bits | both | Ignored. |
| DATA frame from a client | server | Ignored. |
| Connection ends inside a frame, or before FIN | both | The message is incomplete. Close. |
| Server cannot finish a body it began (the file shrank) | server | Close. A status that has been sent cannot be taken back. |
| Response is malformed, on the wrong stream, has DATA before HEADERS or two HEADERS, or does not match its `content-length` | client | Stop and report a protocol error. |

A `400` does not need to end the connection because the frame header is always trustworthy:
by the time a payload turns out to be nonsense, the receiver has already consumed exactly
`Length` bytes and is sitting on the next frame boundary. Error responses have a short
`text/plain` body.

## 8. Limits and what is left open

* No frame is larger than 8 + 65 535 bytes, by construction. Senders SHOULD keep DATA frames
  to 16 384 bytes or less so that a receiver sees progress regularly.
* A header block is at most 65 535 bytes, because it must fit in one frame.

Left open on purpose for a later version: frame types `0x03`–`0xDF`, seven flag bits,
static-table rows 12–127, stream 0 for connection-level frames, request bodies (DATA from the
client is already skipped today), and interleaved streams, which the 32-bit stream ID
already has room for.
