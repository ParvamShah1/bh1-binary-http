# Annotated hexdump of one BH/1 request and response

**Author:** Parvam Shah

These bytes were captured from the real programs with `bcurl -v`. Nothing here is typed by
hand except the explanations. The `date` value is simply when the capture was made.

```
$ printf 'Hello, BH/1!\n' > www/hello.txt
$ ./bserve ./www 9000 &
$ ./bcurl -v localhost:9000/hello.txt
```

| Direction | Bytes | Made of |
|---|---|---|
| Client → server | **70** | 8 preface + (8 + 54) HEADERS |
| Server → client | **113** | (8 + 84) HEADERS + (8 + 13) DATA |

Offsets in each section count from the first byte of that frame. Section numbers like §3
refer to [`SPEC.md`](SPEC.md).

---

## 1. Client → server: preface (8 bytes)

```
0000  42 48 2f 31 0d 0a 0d 0a                           |BH/1....|
```

| Off | Bytes | Value | Meaning |
|---|---|---|---|
| 00 | `42 48 2f 31` | `"BH/1"` | Protocol name and major version |
| 04 | `0d 0a` | CR LF | Ends the "line" |
| 06 | `0d 0a` | CR LF | A blank line, so an HTTP/1.1 server that receives this by mistake replies with an error at once instead of waiting for more (§2) |

The server checks these 8 bytes and sends nothing back. Frames start at the very next byte.

## 2. Client → server: request HEADERS frame (8 + 54 bytes)

```
0000  01 01 00 36 00 00 00 01  82 00 03 47 45 54 83 00  |...6.......GET..|
0010  0a 2f 68 65 6c 6c 6f 2e  74 78 74 84 00 0e 6c 6f  |./hello.txt...lo|
0020  63 61 6c 68 6f 73 74 3a  39 30 30 30 85 00 03 2a  |calhost:9000...*|
0030  2f 2a 86 00 09 62 63 75  72 6c 2f 31 2e 30        |/*...bcurl/1.0|
```

**Frame header** (offsets 00–07)

| Off | Bytes | Field | Value |
|---|---|---|---|
| 00 | `01` | Type | **HEADERS** |
| 01 | `01` | Flags | **FIN**: the request is complete, no body follows |
| 02 | `00 36` | Length | 0x0036 = **54** payload bytes |
| 04 | `00 00 00 01` | Stream ID | **1**, the first request on this connection |

**Header block** (offsets 08–3D: 54 bytes, 5 fields, every name indexed)

| Off | Bytes | Decoded |
|---|---|---|
| 08 | `82` | `0x80 \| 2` → static name 2 = `:method` |
| 09 | `00 03` | value length 3 |
| 0B | `47 45 54` | `GET` |
| 0E | `83` | `0x80 \| 3` → static name 3 = `:path` |
| 0F | `00 0a` | value length 10 |
| 11 | `2f 68 65 6c 6c 6f 2e 74 78 74` | `/hello.txt` |
| 1B | `84` | `0x80 \| 4` → static name 4 = `host` |
| 1C | `00 0e` | value length 14 |
| 1E | `6c 6f … 30 30` | `localhost:9000` |
| 2C | `85` | `0x80 \| 5` → static name 5 = `accept` |
| 2D | `00 03` | value length 3 |
| 2F | `2a 2f 2a` | `*/*` |
| 32 | `86` | `0x80 \| 6` → static name 6 = `user-agent` |
| 33 | `00 09` | value length 9 |
| 35 | `62 63 75 72 6c 2f 31 2e 30` | `bcurl/1.0` |

Check: each field is 1 + 2 + value bytes, so 6 + 13 + 17 + 6 + 12 = **54** = Length. ✔

The top bit of each name byte (`8x`) is what says "this is a table index, not a name
length". The block has no field count and no end marker: the decoder stops when it has used
up all 54 bytes, and a field that would run past byte 3D is a malformed block (→ `400`).

The same request as HTTP/1.1 text is 85 bytes
(`GET /hello.txt HTTP/1.1\r\nHost: localhost:9000\r\nAccept: */*\r\nUser-Agent: bcurl/1.0\r\n\r\n`);
here it is 62, and no part of it has to be searched for a delimiter.

## 3. Server → client: response HEADERS frame (8 + 84 bytes)

```
0000  01 00 00 54 00 00 00 01  81 00 03 32 30 30 88 00  |...T.......200..|
0010  19 74 65 78 74 2f 70 6c  61 69 6e 3b 20 63 68 61  |.text/plain; cha|
0020  72 73 65 74 3d 75 74 66  2d 38 87 00 02 31 33 89  |rset=utf-8...13.|
0030  00 1d 54 68 75 2c 20 30  38 20 4f 63 74 20 32 30  |..Thu, 08 Oct 20|
0040  32 36 20 31 38 3a 32 31  3a 31 35 20 47 4d 54 8a  |26 18:21:15 GMT.|
0050  00 0a 62 73 65 72 76 65  2f 31 2e 30              |..bserve/1.0|
```

**Frame header** (offsets 00–07)

| Off | Bytes | Field | Value |
|---|---|---|---|
| 00 | `01` | Type | **HEADERS** |
| 01 | `00` | Flags | none: FIN is **not** set, because a body follows in DATA frames |
| 02 | `00 54` | Length | 0x0054 = **84** payload bytes |
| 04 | `00 00 00 01` | Stream ID | **1**: this answers the request on stream 1 |

**Header block** (offsets 08–5B: 84 bytes, 5 fields)

| Off | Bytes | Decoded |
|---|---|---|
| 08 | `81` | `0x80 \| 1` → static name 1 = `:status` (always the first field of a response) |
| 09 | `00 03` | value length 3 |
| 0B | `32 30 30` | `200` (ASCII digits, not a binary number) |
| 0E | `88` | `0x80 \| 8` → static name 8 = `content-type` |
| 0F | `00 19` | value length 25 |
| 11 | `74 65 … 2d 38` | `text/plain; charset=utf-8` |
| 2A | `87` | `0x80 \| 7` → static name 7 = `content-length` |
| 2B | `00 02` | value length 2 |
| 2D | `31 33` | `13` |
| 2F | `89` | `0x80 \| 9` → static name 9 = `date` |
| 30 | `00 1d` | value length 29 |
| 32 | `54 68 … 4d 54` | `Thu, 08 Oct 2026 18:21:15 GMT` |
| 4F | `8a` | `0x80 \| 10` → static name 10 = `server` |
| 50 | `00 0a` | value length 10 |
| 52 | `62 73 65 72 76 65 2f 31 2e 30` | `bserve/1.0` |

Check: 6 + 28 + 5 + 32 + 13 = **84** = Length. ✔

## 4. Server → client: DATA frame (8 + 13 bytes)

```
0000  02 01 00 0d 00 00 00 01  48 65 6c 6c 6f 2c 20 42  |........Hello, B|
0010  48 2f 31 21 0a                                    |H/1!.|
```

| Off | Bytes | Field | Value |
|---|---|---|---|
| 00 | `02` | Type | **DATA** |
| 01 | `01` | Flags | **FIN**: last frame of the response |
| 02 | `00 0d` | Length | 0x000d = **13** payload bytes |
| 04 | `00 00 00 01` | Stream ID | **1** |
| 08 | `48 65 6c 6c 6f 2c 20 42 48 2f 31 21 0a` | Payload | `Hello, BH/1!` and a line feed: the file, byte for byte |

13 bytes received = `content-length: 13`. ✔ `bcurl` checks this itself and exits with
status 8 if they differ.

## 5. What happens next

FIN on stream 1 ends the response, but **not** the connection. The client can send another
HEADERS frame on stream 2 straight away (`bcurl url1 url2` does exactly that), with no new
preface. Here `bcurl` has nothing more to ask for, so it closes the socket; the server reads
end-of-file on a frame boundary and ends that connection's thread.

## 6. The same exchange with greasing (`bserve -g`)

With `-g` the server sends frames of types no BH/1 implementation knows. This one arrived
just before the DATA frame in a real run:

```
< UNKNOWN frame: type=0xf2 flags=0xe5 [FIN] len=7 stream=0
<   0000  f2 e5 00 07 00 00 00 00  c9 b7 a5 a9 ed de b3     |...............|
```

| Off | Bytes | Field | What the client does with it |
|---|---|---|---|
| 00 | `f2` | Type | Not `01` or `02`, so the frame is unknown |
| 01 | `e5` | Flags | Ignored. Bit `01` (FIN) happens to be set here, and it still does **not** end the response |
| 02 | `00 07` | Length | The only field that is used: read 7 more bytes and discard them |
| 04 | `00 00 00 00` | Stream ID | Ignored |
| 08 | `c9 b7 a5 a9 ed de b3` | Payload | Random bytes, discarded |

The client then reads the real DATA frame as if nothing had happened and prints the same
13 bytes. This is the §4 skip rule working on the wire.
