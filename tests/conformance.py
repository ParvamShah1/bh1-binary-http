#!/usr/bin/env python3
"""
BH/1 conformance tests.  Author: Parvam Shah

This file is a second implementation of BH/1, written from SPEC.md and sharing
no code with the C programs.  It plays the client against ./bserve and a
deliberately awkward server against ./bcurl, so neither C program is only ever
tested against its own partner.

    python3 tests/conformance.py        (or: make test)
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BSERVE = os.path.join(REPO, "bserve")
BCURL = os.path.join(REPO, "bcurl")

# ---------------------------------------------------------------- wire format

PREFACE = b"BH/1\r\n\r\n"
HEADERS, DATA = 0x01, 0x02
FIN = 0x01
NAMES = [None, ":status", ":method", ":path", "host", "accept", "user-agent",
         "content-length", "content-type", "date", "server", "allow"]


def frame(ftype, flags, stream, payload=b""):
    return struct.pack("!BBHI", ftype, flags, len(payload), stream) + payload


def field(name, value, literal=False):
    name = name.encode() if isinstance(name, str) else name
    value = value.encode() if isinstance(value, str) else value
    if not literal and name.decode("latin-1") in NAMES[1:]:
        head = bytes([0x80 | NAMES.index(name.decode())])
    else:
        head = bytes([len(name)]) + name
    return head + struct.pack("!H", len(value)) + value


def block(pairs):
    return b"".join(field(n, v) for n, v in pairs)


def parse_block(payload):
    out, i = [], 0
    while i < len(payload):
        first = payload[i]
        i += 1
        if first & 0x80:
            index = first & 0x7F
            assert 1 <= index < len(NAMES), "bad static index %d" % index
            name = NAMES[index]
        else:
            assert first > 0, "zero-length literal name"
            name = payload[i:i + first].decode("ascii")
            assert len(name) == first, "truncated name"
            i += first
        assert i + 2 <= len(payload), "truncated value length"
        (vlen,) = struct.unpack_from("!H", payload, i)
        i += 2
        assert i + vlen <= len(payload), "truncated value"
        out.append((name, payload[i:i + vlen].decode("latin-1")))
        i += vlen
    return out


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            if buf:
                raise EOFError("EOF inside a frame")
            return None
        buf += part
    return buf


def read_frame(sock):
    head = recv_exact(sock, 8)
    if head is None:
        return None
    ftype, flags, length, stream = struct.unpack("!BBHI", head)
    payload = recv_exact(sock, length) if length else b""
    if payload is None:
        raise EOFError("EOF before payload")
    return ftype, flags, stream, payload


# ------------------------------------------------------------ BH/1 test client

class Response:
    def __init__(self):
        self.status = None
        self.fields = []
        self.body = b""
        self.data_frames = []      # (length, flags) of every DATA frame
        self.fin_on_headers = False
        self.unknown = 0           # unknown-type frames skipped on the way

    def get(self, name):
        return dict(self.fields).get(name)


class Conn:
    def __init__(self, port, preface=PREFACE):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.sendall(preface)

    def send(self, data):
        self.sock.sendall(data)

    def request(self, stream, pairs, flags=FIN):
        self.send(frame(HEADERS, flags, stream, block(pairs)))

    def get(self, stream, path, method="GET"):
        self.request(stream, [(":method", method), (":path", path), ("host", "test")])

    def response(self, stream):
        r = Response()
        while True:
            fr = read_frame(self.sock)
            assert fr is not None, "server closed mid-response"
            ftype, flags, sid, payload = fr
            if ftype not in (HEADERS, DATA):
                r.unknown += 1
                continue
            assert sid == stream, "response on stream %d, expected %d" % (sid, stream)
            if ftype == HEADERS:
                assert r.status is None, "second HEADERS frame"
                r.fields = parse_block(payload)
                assert r.fields[0][0] == ":status", "first field is not :status"
                assert len(r.fields[0][1]) == 3 and r.fields[0][1].isdigit()
                r.status = int(r.fields[0][1])
                r.fin_on_headers = bool(flags & FIN)
            else:
                assert r.status is not None, "DATA before HEADERS"
                r.body += payload
                r.data_frames.append((len(payload), flags))
            if flags & FIN:
                return r

    def fetch(self, stream, path, method="GET"):
        self.get(stream, path, method)
        return self.response(stream)

    def is_closed(self):
        try:
            return self.sock.recv(1) == b""
        except (ConnectionResetError, BrokenPipeError):
            return True

    def close(self):
        self.sock.close()


# ------------------------------------------------------------------- fixtures

BIG = bytes((i * 7 + (i >> 8)) & 0xFF for i in range(200_000))


def make_docroot(base):
    root = os.path.join(base, "root")
    os.makedirs(os.path.join(root, "sub"))

    def put(rel, data):
        with open(os.path.join(root, rel), "wb") as fh:
            fh.write(data)

    put("hello.txt", b"hello\n")
    put("empty.txt", b"")
    put("index.html", b"<h1>root index</h1>\n")
    put("sub/index.html", b"<p>sub index</p>\n")
    put("sub/note.txt", b"note\n")
    put("big.bin", BIG)
    put("sp ace.txt", b"space\n")
    with open(os.path.join(base, "secret.txt"), "wb") as fh:
        fh.write(b"TOP SECRET\n")
    os.symlink(os.path.join(base, "secret.txt"), os.path.join(root, "leak"))
    return root


def start_bserve(root, *flags):
    proc = subprocess.Popen([BSERVE, *flags, root, "0"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    line = proc.stdout.readline().decode()
    assert "on port" in line, "bserve did not start: %r" % line
    return proc, int(line.rsplit(" ", 1)[1])


class Mock:
    """A BH/1 server for bcurl. responder(conn, stream, fields, nth) writes the reply."""

    def __init__(self, responder):
        self.responder = responder
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self.requests = []         # (connection number, stream, flags, fields)
        self.errors = []
        threading.Thread(target=self._accept, daemon=True).start()

    def url(self, path):
        return "127.0.0.1:%d%s" % (self.port, path)

    def _accept(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn, self.connections), daemon=True).start()

    def _serve(self, conn, number):
        try:
            if recv_exact(conn, 8) != PREFACE:
                self.errors.append("bad preface")
                return
            while True:
                fr = read_frame(conn)
                if fr is None:
                    return
                ftype, flags, stream, payload = fr
                if ftype != HEADERS:
                    continue
                fields = parse_block(payload)
                self.requests.append((number, stream, flags, fields))
                if self.responder(conn, stream, dict(fields), len(self.requests)) is False:
                    return
        except Exception as exc:  # noqa: BLE001 - reported by the test
            self.errors.append(repr(exc))
        finally:
            conn.close()

    def close(self):
        self.listener.close()


def reply(conn, stream, body=b"ok\n", status="200", extra=(), length=None):
    pairs = [(":status", status), ("content-type", "text/plain"),
             ("content-length", str(len(body) if length is None else length))]
    conn.sendall(frame(HEADERS, 0, stream, block(pairs + list(extra))))
    conn.sendall(frame(DATA, FIN, stream, body))


def bcurl(*args):
    return subprocess.run([BCURL, *args], capture_output=True, timeout=20)


# ---------------------------------------------------------------------- tests

TESTS = []
PORT = None        # bserve under test
GREASE_PORT = None  # bserve -g


def test(fn):
    TESTS.append(fn)
    return fn


# --- bserve, driven by the Python client

@test
def server_basic_get():
    c = Conn(PORT)
    r = c.fetch(1, "/hello.txt")
    assert r.status == 200 and r.body == b"hello\n"
    assert r.get("content-length") == "6"
    assert r.get("content-type").startswith("text/plain")
    assert r.get("server") and r.get("date")
    assert r.data_frames[-1][1] & FIN and not r.fin_on_headers
    c.close()


@test
def server_keep_alive_and_any_stream_id():
    c = Conn(PORT)
    for stream, path, want in [(1, "/hello.txt", b"hello\n"), (2, "/sub/note.txt", b"note\n"),
                               (77777, "/hello.txt", b"hello\n"), (0xFFFFFFFF, "/sub/note.txt", b"note\n")]:
        r = c.fetch(stream, path)
        assert r.status == 200 and r.body == want
    c.close()


@test
def server_pipelining_answers_in_order():
    c = Conn(PORT)
    paths = ["/hello.txt", "/missing", "/sub/note.txt", "/big.bin"]
    c.send(b"".join(frame(HEADERS, FIN, i + 1, block([(":method", "GET"), (":path", p)]))
                    for i, p in enumerate(paths)))
    got = [c.response(i + 1) for i in range(len(paths))]
    assert [r.status for r in got] == [200, 404, 200, 200]
    assert got[0].body == b"hello\n" and got[2].body == b"note\n" and got[3].body == BIG
    c.close()


@test
def server_head_has_no_body():
    c = Conn(PORT)
    r = c.fetch(1, "/big.bin", "HEAD")
    assert r.status == 200 and r.fin_on_headers and not r.data_frames
    assert r.get("content-length") == str(len(BIG))
    assert c.fetch(2, "/hello.txt").body == b"hello\n"   # stream still in sync
    c.close()


@test
def server_empty_file():
    c = Conn(PORT)
    r = c.fetch(1, "/empty.txt")
    assert r.status == 200 and r.body == b"" and r.get("content-length") == "0"
    c.close()


@test
def server_large_body_spans_frames():
    c = Conn(PORT)
    r = c.fetch(1, "/big.bin")
    assert r.body == BIG
    assert len(r.data_frames) > 1 and all(n <= 16384 for n, _ in r.data_frames)
    assert [bool(fl & FIN) for _, fl in r.data_frames] == [False] * (len(r.data_frames) - 1) + [True]
    c.close()


@test
def server_directory_index():
    c = Conn(PORT)
    assert c.fetch(1, "/").body == b"<h1>root index</h1>\n"
    assert c.fetch(2, "/sub/").body == b"<p>sub index</p>\n"
    assert c.fetch(3, "/sub").body == b"<p>sub index</p>\n"
    assert c.fetch(3, "/").get("content-type").startswith("text/html")
    c.close()


@test
def server_percent_decoding_and_query():
    c = Conn(PORT)
    assert c.fetch(1, "/sp%20ace.txt").body == b"space\n"
    assert c.fetch(2, "/hello.txt?x=1&y=%zz").body == b"hello\n"
    assert c.fetch(3, "/%68ello.txt").body == b"hello\n"
    c.close()


@test
def server_404_and_no_escape_from_root():
    c = Conn(PORT)
    for i, path in enumerate(["/nope.txt", "/../secret.txt", "/%2e%2e/secret.txt",
                              "/sub/../../secret.txt", "/leak", "/hello.txt/", "/sub/%2e%2e%2f%2e%2e/secret.txt"]):
        r = c.fetch(i + 1, path)
        assert r.status == 404, "%s gave %s" % (path, r.status)
        assert b"SECRET" not in r.body
    assert c.fetch(99, "/hello.txt").status == 200
    c.close()


@test
def server_405_with_allow():
    c = Conn(PORT)
    for i, method in enumerate(["POST", "DELETE", "get"]):
        r = c.fetch(i + 1, "/hello.txt", method)
        assert r.status == 405 and r.get("allow") == "GET, HEAD"
    assert c.fetch(9, "/hello.txt").status == 200
    c.close()


@test
def server_400_keeps_the_connection():
    get, path = field(":method", "GET"), field(":path", "/hello.txt")
    bad = {
        "missing :path": get,
        "missing :method": path,
        "empty block": b"",
        "duplicate :method": get + get + path,
        "pseudo after regular": get + field("host", "x") + path,
        ":status in a request": get + path + field(":status", "200"),
        "index 0": get + path + b"\x80\x00\x00",
        "index past the table": get + path + b"\xff\x00\x00",
        "zero-length literal name": get + path + b"\x00\x00\x00",
        "truncated value": get + path + b"\x84\x00\x09abc",
        "truncated value length": get + path + b"\x84\x00",
        "truncated literal name": get + path + b"\x09abc",
        "uppercase literal name": get + path + field("X-Thing", "1"),
        "colon in literal name": get + path + field(":scheme", "http"),
        "LF in a value": get + path + field("host", "a\nb"),
        "NUL in a value": get + path + field("host", "a\x00b"),
        "path without a leading slash": get + field(":path", "hello.txt"),
        "bad percent escape": get + field(":path", "/a%zz"),
        "encoded NUL in path": get + field(":path", "/a%00b"),
    }
    c = Conn(PORT)
    stream = 0
    for what, payload in bad.items():
        stream += 1
        c.send(frame(HEADERS, FIN, stream, payload))
        assert c.response(stream).status == 400, what
        stream += 1
        assert c.fetch(stream, "/hello.txt").body == b"hello\n", "connection lost after: " + what
    stream += 1
    c.request(stream, [(":method", "GET"), (":path", "/hello.txt")], flags=0)   # no FIN
    assert c.response(stream).status == 400
    assert c.fetch(stream + 1, "/hello.txt").status == 200
    c.close()


@test
def server_skips_unknown_frame_types():
    c = Conn(PORT)
    c.send(frame(0x00, 0, 0, b"type zero is not defined"))
    c.send(frame(0x7F, 0xFF, 0, b"x" * 300))
    c.send(frame(0xE3, FIN, 5, b""))
    c.send(frame(0x03, 0, 1, b"\xff" * 65535))
    assert c.fetch(1, "/hello.txt").body == b"hello\n"
    c.send(frame(0xFF, FIN, 2, b"between requests"))
    assert c.fetch(2, "/sub/note.txt").body == b"note\n"
    c.close()


@test
def server_ignores_unknown_flags_and_client_data():
    c = Conn(PORT)
    c.request(1, [(":method", "GET"), (":path", "/hello.txt")], flags=0xFF)
    assert c.response(1).body == b"hello\n"
    c.send(frame(DATA, FIN, 1, b"a body nobody asked for"))
    c.send(frame(DATA, 0, 0, b""))
    assert c.fetch(2, "/hello.txt").body == b"hello\n"
    c.close()


@test
def server_accepts_literal_names():
    c = Conn(PORT)
    c.send(frame(HEADERS, FIN, 1, field(":method", "GET") + field(":path", "/hello.txt") +
                 field("x-trace-id", "abc123") + field("host", "spelled-out", literal=True)))
    assert c.response(1).body == b"hello\n"
    c.close()


@test
def server_wrong_preface_is_closed_silently():
    for preface in [b"GET / HT", b"BH/2\r\n\r\n", b"BH/1\r\n\x1a\n", b"bh/1\r\n\r\n"]:
        c = Conn(PORT, preface=preface)
        c.send(frame(HEADERS, FIN, 1, block([(":method", "GET"), (":path", "/hello.txt")])))
        assert c.is_closed(), "replied to preface %r" % preface
        c.close()


@test
def server_request_on_stream_zero_closes():
    c = Conn(PORT)
    c.get(0, "/hello.txt")
    assert c.is_closed()
    c.close()


@test
def server_survives_truncated_frames():
    for junk in [b"\x01", struct.pack("!BBHI", HEADERS, FIN, 500, 1) + b"short", PREFACE[:3]]:
        c = Conn(PORT, preface=b"") if junk == PREFACE[:3] else Conn(PORT)
        c.send(junk)
        c.close()
    c = Conn(PORT)
    assert c.fetch(1, "/hello.txt").status == 200
    c.close()


@test
def server_connections_are_independent():
    idle = Conn(PORT)                 # opened first, says nothing
    half = Conn(PORT)
    half.send(b"\x01\x01")            # stuck halfway through a frame header
    busy = Conn(PORT)
    assert busy.fetch(1, "/hello.txt").body == b"hello\n"
    assert idle.fetch(1, "/sub/note.txt").body == b"note\n"
    for c in (idle, half, busy):
        c.close()


@test
def server_grease_mode_sends_skippable_frames():
    c = Conn(GREASE_PORT)
    unknown = 0
    for stream, path, want in [(1, "/hello.txt", b"hello\n"), (2, "/big.bin", BIG), (3, "/nope", None)]:
        r = c.fetch(stream, path)
        unknown += r.unknown
        if want is not None:
            assert r.status == 200 and r.body == want
        else:
            assert r.status == 404
    assert unknown >= 3, "expected greased frames, saw %d" % unknown
    c.close()


# --- bcurl, driven by the Python mock server

@test
def client_sends_a_wellformed_request():
    m = Mock(lambda conn, stream, fields, nth: reply(conn, stream, b"payload\n"))
    p = bcurl(m.url("/a/b.txt?q=1"))
    assert p.returncode == 0 and p.stdout == b"payload\n", p
    assert not m.errors, m.errors
    (_, stream, flags, fields), = m.requests
    assert stream == 1 and flags & FIN
    names = [n for n, _ in fields]
    assert names[:2] == [":method", ":path"] or names[:2] == [":path", ":method"]
    d = dict(fields)
    assert d[":method"] == "GET" and d[":path"] == "/a/b.txt?q=1"
    assert d["host"] == "127.0.0.1:%d" % m.port
    m.close()


@test
def client_default_path_is_slash():
    m = Mock(lambda conn, stream, fields, nth: reply(conn, stream))
    assert bcurl("127.0.0.1:%d" % m.port).returncode == 0
    assert dict(m.requests[0][3])[":path"] == "/"
    m.close()


@test
def client_copes_with_an_awkward_server():
    body = bytes(range(256)) * 3

    def responder(conn, stream, fields, nth):
        out = [frame(0xE7, FIN, stream, b"grease with FIN set"),
               frame(0x00, 0xFF, 0, b""),
               frame(HEADERS, 0xF0, stream, block([(":status", "200"), ("content-length", str(len(body)))])),
               frame(0x55, 0, 12345, b"z" * 1000)]
        out += [frame(DATA, 0x80, stream, body[i:i + 1]) for i in range(40)]
        out += [frame(DATA, 0, stream, b""), frame(DATA, 0, stream, body[40:]),
                frame(0xFE, FIN, stream, b"\x00"), frame(DATA, FIN | 0x40, stream, b"")]
        wire = b"".join(out)
        for i in range(0, len(wire), 7):      # dribble it out, splitting frame headers
            conn.sendall(wire[i:i + 7])

    m = Mock(responder)
    p = bcurl(m.url("/x"))
    assert p.returncode == 0 and p.stdout == body, (p.returncode, p.stderr)
    m.close()


@test
def client_reuses_one_connection():
    m = Mock(lambda conn, stream, fields, nth: reply(conn, stream, fields[":path"].encode() + b"\n"))
    p = bcurl(m.url("/one"), m.url("/two"), m.url("/three"))
    assert p.returncode == 0 and p.stdout == b"/one\n/two\n/three\n", p
    assert m.connections == 1, "%d connections" % m.connections
    assert [(n, s) for n, s, _, _ in m.requests] == [(1, 1), (1, 2), (1, 3)]
    m.close()


@test
def client_exit_22_on_error_status_but_keeps_going():
    def responder(conn, stream, fields, nth):
        if fields[":path"] == "/bad":
            reply(conn, stream, b"gone\n", status="404")
        else:
            reply(conn, stream, b"fine\n")

    m = Mock(responder)
    assert bcurl(m.url("/bad")).returncode == 22
    p = bcurl(m.url("/bad"), m.url("/good"))
    assert p.returncode == 22 and p.stdout.endswith(b"fine\n"), p
    assert bcurl(m.url("/good")).returncode == 0
    m.close()


@test
def client_head():
    def responder(conn, stream, fields, nth):
        conn.sendall(frame(HEADERS, FIN, stream, block([(":status", "200"), ("content-length", "4096")])))

    m = Mock(responder)
    p = bcurl("-I", m.url("/thing"))
    assert p.returncode == 0, p
    assert dict(m.requests[0][3])[":method"] == "HEAD"
    assert b"BH/1 200" in p.stdout and b"content-length: 4096" in p.stdout
    m.close()


@test
def client_show_fields_and_literal_names():
    m = Mock(lambda conn, stream, fields, nth: reply(conn, stream, b"body\n", extra=[("x-served-by", "mock")]))
    p = bcurl("-i", m.url("/"))
    assert p.returncode == 0
    assert p.stdout == b"BH/1 200\ncontent-type: text/plain\ncontent-length: 5\nx-served-by: mock\n\nbody\n", p.stdout
    m.close()


@test
def client_exit_8_on_protocol_errors():
    def short_body(conn, stream, fields, nth):
        reply(conn, stream, b"abc", length=10)

    def hangs_up(conn, stream, fields, nth):
        conn.sendall(frame(HEADERS, 0, stream, block([(":status", "200")])) + frame(DATA, 0, stream, b"half"))
        return False

    def cut_frame(conn, stream, fields, nth):
        conn.sendall(struct.pack("!BBHI", DATA, FIN, 100, stream) + b"only this")
        return False

    def wrong_stream(conn, stream, fields, nth):
        reply(conn, stream + 1)

    def data_first(conn, stream, fields, nth):
        conn.sendall(frame(DATA, FIN, stream, b"x"))

    def two_heads(conn, stream, fields, nth):
        head = frame(HEADERS, 0, stream, block([(":status", "200")]))
        conn.sendall(head + head + frame(DATA, FIN, stream, b""))

    def bad_index(conn, stream, fields, nth):
        conn.sendall(frame(HEADERS, FIN, stream, block([(":status", "200")]) + b"\xbf\x00\x00"))

    def status_not_first(conn, stream, fields, nth):
        conn.sendall(frame(HEADERS, FIN, stream, block([("server", "x"), (":status", "200")])))

    def silent(conn, stream, fields, nth):
        return False

    for responder in (short_body, hangs_up, cut_frame, wrong_stream, data_first, two_heads,
                      bad_index, status_not_first, silent):
        m = Mock(responder)
        code = bcurl(m.url("/")).returncode
        assert code == 8, "%s: exit %d" % (responder.__name__, code)
        m.close()


@test
def client_exit_7_when_nothing_listens():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert bcurl("127.0.0.1:%d/" % port).returncode == 7


# --- the two C programs together

@test
def both_programs_together():
    p = bcurl("127.0.0.1:%d/big.bin" % GREASE_PORT, "127.0.0.1:%d/hello.txt" % GREASE_PORT)
    assert p.returncode == 0 and p.stdout == BIG + b"hello\n"
    assert bcurl("127.0.0.1:%d/nope" % PORT).returncode == 22
    assert bcurl("localhost:%d/sub/" % PORT).stdout == b"<p>sub index</p>\n"


def main():
    global PORT, GREASE_PORT
    for binary in (BSERVE, BCURL):
        if not os.access(binary, os.X_OK):
            sys.exit("missing %s - run `make` first" % binary)

    failed = 0
    with tempfile.TemporaryDirectory() as base:
        root = make_docroot(base)
        plain, PORT = start_bserve(root)
        greasy, GREASE_PORT = start_bserve(root, "-g")
        try:
            for fn in TESTS:
                try:
                    fn()
                    print("ok    %s" % fn.__name__)
                except Exception as exc:  # noqa: BLE001
                    failed += 1
                    print("FAIL  %s: %s: %s" % (fn.__name__, type(exc).__name__, exc))
            for proc in (plain, greasy):
                if proc.poll() is not None:
                    failed += 1
                    print("FAIL  bserve exited during the run (status %s)" % proc.returncode)
        finally:
            for proc in (plain, greasy):
                proc.kill()
                proc.wait()
                proc.stdout.close()

    print("\n%d tests, %d failed" % (len(TESTS), failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
