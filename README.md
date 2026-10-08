# bh1-binary-http

**Author:** Parvam Shah · Network Architecture course project

**BH/1** is a small binary framing protocol that carries HTTP semantics, together with a
static file server (`bserve`) and a client (`bcurl`) that speak it. The project is about three
design decisions: which fields go in the frame header and how wide they are, how header names
are numbered so they need not be spelled out, and how a receiver gets past frame types it has
never heard of.

| Deliverable | Where |
|---|---|
| 1. The specification | [`SPEC.md`](SPEC.md) |
| 2. The program | [`src/`](src) → `bserve` (server) and `bcurl` (client) |
| 3. Annotated hexdump | [`HEXDUMP.md`](HEXDUMP.md) |

## The protocol in one screen

```
preface   42 48 2F 31 0D 0A 0D 0A                 "BH/1\r\n\r\n", client only

frame     +--------+--------+-----------------+
          | Type 8 | Flags 8|    Length 16    |   8-byte header,
          +--------+--------+-----------------+   then Length bytes of payload
          |           Stream ID 32            |
          +-----------------------------------+

types     0x01 HEADERS   0x02 DATA   anything else: skip Length bytes, not an error
flags     0x01 FIN (last frame of the message)

field     1xxxxxxx                 name = row x of the static table (11 names)
          0xxxxxxx + x bytes       literal name
          then a 16-bit value length and the value
```

## Build and run

```sh
make                                   # builds ./bserve and ./bcurl (C11, no dependencies)
./bserve ./www 9000                    # serve ./www on port 9000
./bcurl -v localhost:9000/index.html   # fetch it; -v hexdumps every frame to stderr
```

`bserve [-v] [-g] ROOT PORT`

* `-v` traces every frame.
* `-g` greases: before each response (and before the last DATA frame) it sends a frame of an
  unknown type, which immediately breaks any client that does not skip unknown frames.
* `PORT` may be `0` to let the OS choose; the port is printed on startup.

`bcurl [-v] [-I] [-i] URL...`

* `-I` sends HEAD and prints the response fields; `-i` prints the fields before the body.
* A URL is `host[:port][/path]`. Several URLs for the same host and port are fetched over
  **one** connection, on streams 1, 2, 3, …
* Exit status: `0` success, `22` some response was 4xx/5xx, `7` could not connect,
  `8` the server broke the protocol.

### Example

```
$ ./bcurl -v localhost:9000/hello.txt
> PREFACE (8 bytes)
>   0000  42 48 2f 31 0d 0a 0d 0a                           |BH/1....|
> HEADERS frame: type=0x01 flags=0x01 [FIN] len=54 stream=1
>   0000  01 01 00 36 00 00 00 01  82 00 03 47 45 54 83 00  |...6.......GET..|
...
< DATA frame: type=0x02 flags=0x01 [FIN] len=13 stream=1
<   0000  02 01 00 0d 00 00 00 01  48 65 6c 6c 6f 2c 20 42  |........Hello, B|
<   0010  48 2f 31 21 0a                                    |H/1!.|
Hello, BH/1!
```

[`HEXDUMP.md`](HEXDUMP.md) explains every byte of this exchange.

## Tests

```sh
make test
```

`tests/conformance.py` is a **second implementation of BH/1, in Python, written from
`SPEC.md`** and sharing no code with the C programs. It is the client when testing `bserve`
and a deliberately awkward server when testing `bcurl`, so each C program is checked against
something other than its partner. 29 tests cover:

* keep-alive, pipelining, arbitrary stream IDs, independent concurrent connections
* HEAD, empty files, a 200 kB body split over many DATA frames, directory indexes
* `400` for nineteen kinds of malformed request, each followed by a normal request on the
  same connection; `404`; `405` with `allow`
* path traversal with `..`, encoded `..`, and a symlink pointing out of the root
* unknown frame types and unknown flag bits in both directions, including `bserve -g`
* a wrong preface, truncated frames, and connections dropped mid-message
* `bcurl`'s one-connection rule and its exit codes for every protocol error

## Layout

```
SPEC.md            the protocol
HEXDUMP.md         one real exchange, byte by byte
src/bh1.[ch]       framing, header-block encoder/decoder, hexdump tracer (shared)
src/bserve.c       server: one thread per connection, requests answered in order
src/bcurl.c        client
tests/             independent Python conformance suite
www/               sample document root
.github/           CI: build and test on Ubuntu and macOS
```
