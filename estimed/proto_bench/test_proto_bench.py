"""Offline tests for proto_bench.py's own logic (no CSE, no broker; loopback sockets on kernel-chosen ports only).

Run:  $VENV/bin/python3 -m unittest -v test_proto_bench.py   (VENV: the venv with acmecse, websockets, paho)
Oracles that are not our code: CoAPthon's serializer (the library ACME's CoAP server uses), websockets' frame
serializer, RFC 7252 Appendix A example messages, hand-computed MQTT 3.1.1 sizes.
"""
import contextlib
import json
import random
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import coap_min as coap  # noqa: E402
import proto_bench as pb  # noqa: E402


# ------------------------------------------------------------------------------------------------ CoAP codec
def coapthon_decode(raw: bytes):
    from coapthon.serializer import Serializer
    from acmecse.helpers.CoAPthonTools import registerOneM2MOptions, registerOneM2MContentTypes
    registerOneM2MOptions()
    registerOneM2MContentTypes()
    return Serializer().deserialize(raw, ("127.0.0.1", 5683))


def cross_check(msg: coap.Message) -> list[str]:
    """Encode with ours, decode with CoAPthon; list every field that differs."""
    raw = coap.encode(msg)
    m = coapthon_decode(raw)
    if isinstance(m, int):
        return [f"coapthon refused the datagram (code {m})"]
    diffs = []
    if m.code != msg.code:
        diffs.append(f"code {m.code} != {msg.code}")
    if m.mid != msg.mid:
        diffs.append(f"mid {m.mid} != {msg.mid}")
    tok = m.token if isinstance(m.token, (bytes, bytearray)) else (m.token or b"")
    if bytes(tok) != msg.token:
        diffs.append(f"token {tok!r} != {msg.token!r}")
    theirs = sorted(o.number for o in m.options)
    ours = sorted(n for n, _ in msg.options)
    if theirs != ours:
        diffs.append(f"option numbers {theirs} != {ours}")
    pl = m.payload if isinstance(m.payload, (bytes, bytearray)) else (m.payload or "").encode()
    if bytes(pl or b"") != msg.payload:
        diffs.append("payload differs")
    return diffs


class CoapCodec(unittest.TestCase):
    # RFC 7252 Appendix A, first example: CON GET MID 0x7d34 Uri-Path "temperature" / ACK 2.05 "22.3 C"
    RFC_GET = bytes.fromhex("40017d34bb") + b"temperature"
    RFC_ACK = bytes.fromhex("60457d34ff") + b"22.3 C"
    # same request with a 1-byte token 0x20 (TKL=1)
    RFC_GET_TOKEN = bytes.fromhex("41017d3420bb") + b"temperature"

    def test_rfc7252_vectors_encode(self):
        m = coap.Message(mtype=coap.CON, code=coap.GET, mid=0x7D34).add(coap.URI_PATH, "temperature")
        self.assertEqual(coap.encode(m), self.RFC_GET)
        a = coap.Message(mtype=coap.ACK, code=coap.CONTENT, mid=0x7D34, payload=b"22.3 C")
        self.assertEqual(coap.encode(a), self.RFC_ACK)
        t = coap.Message(mtype=coap.CON, code=coap.GET, mid=0x7D34, token=b"\x20").add(coap.URI_PATH, "temperature")
        self.assertEqual(coap.encode(t), self.RFC_GET_TOKEN)

    def test_rfc7252_vectors_decode(self):
        m = coap.decode(self.RFC_GET)
        self.assertEqual((m.mtype, m.code, m.mid, m.token), (coap.CON, coap.GET, 0x7D34, b""))
        self.assertEqual(m.get_str(coap.URI_PATH), "temperature")
        a = coap.decode(self.RFC_ACK)
        self.assertEqual((a.mtype, coap.code_str(a.code), a.payload), (coap.ACK, "2.05", b"22.3 C"))

    def test_extended_deltas_by_hand(self):
        # first option 279 (oneM2M-FR): delta 279 >= 269 -> nibble 14, 2 bytes 279-269 = 10
        m = coap.Message(mid=1).add(coap.OM2M_FR, "Cx")
        self.assertEqual(coap.encode(m), bytes.fromhex("40000001") + bytes([0xE2, 0x00, 0x0A]) + b"Cx")
        # Uri-Path (11) then oneM2M-FR: delta 268 -> nibble 13, 1 byte 268-13 = 255
        m = coap.Message(mid=1).add(coap.URI_PATH, "a").add(coap.OM2M_FR, "C")
        self.assertEqual(coap.encode(m), bytes.fromhex("40000001") + b"\xb1a" + bytes([0xD1, 0xFF]) + b"C")
        # 13-byte value -> length nibble 13 + 1 extension byte 0
        m = coap.Message(mid=1).add(coap.URI_PATH, "x" * 13)
        self.assertEqual(coap.encode(m)[4:6], bytes([0xBD, 0x00]))

    def test_round_trip_random(self):
        rnd = random.Random(7)
        nums = [coap.URI_PATH, coap.CONTENT_FORMAT, coap.URI_QUERY, coap.ACCEPT, coap.BLOCK1, coap.BLOCK2,
                coap.OM2M_TY, coap.OM2M_RVI, coap.OM2M_FR, coap.OM2M_RQI, coap.OM2M_RSC, coap.SIZE1]
        for _ in range(300):
            m = coap.Message(mtype=rnd.randrange(4), code=rnd.choice([1, 2, 3, 4, 65, 69, 132, 160]),
                             mid=rnd.randrange(65536), token=rnd.randbytes(rnd.randrange(9)))
            for _ in range(rnd.randrange(8)):
                n = rnd.choice(nums)
                m.add(n, rnd.randrange(70000) if n in coap.UINT_OPTIONS else rnd.randbytes(rnd.choice([0, 1, 12, 13, 14, 268, 269, 300])))
            m.payload = rnd.randbytes(rnd.choice([0, 1, 50, 1024]))
            d = coap.decode(coap.encode(m))
            self.assertEqual((d.mtype, d.code, d.mid, d.token, d.payload), (m.mtype, m.code, m.mid, m.token, m.payload))
            self.assertEqual(d.options, sorted(m.options, key=lambda o: o[0]))

    def test_against_coapthon(self):
        m = coap.Message(mtype=coap.CON, code=coap.POST, mid=4242, token=b"\x01\x02\x03\x04")
        for seg in ("proto-p", "pb-x", "data"):
            m.add(coap.URI_PATH, seg)
        m.add(coap.CONTENT_FORMAT, 50).add(coap.ACCEPT, 50).add(coap.OM2M_FR, "Cbcoaprc123456")
        m.add(coap.OM2M_RQI, "rq0123456789ab").add(coap.OM2M_RVI, "4").add(coap.OM2M_TY, 4)
        m.add(coap.URI_QUERY, "fu=1").add(coap.URI_QUERY, "lbl=bench:small")
        m.payload = json.dumps({"m2m:cin": {"con": "x" * 100}}).encode()
        self.assertEqual(cross_check(m), [])

    def test_planted_fault_is_caught(self):
        """CONTROL: an encoder with the wrong 8-bit extension base (12 instead of 13) must fail the cross-check
        and the hand-computed vector."""
        # Uri-Query (15): delta 15 -> nibble 13 + ext 2; then oneM2M-FR: delta 264 -> nibble 13 + ext 251
        m = coap.Message(code=coap.GET, mid=1).add(coap.URI_QUERY, "fu=1").add(coap.OM2M_FR, "C")
        good = bytes.fromhex("40010001") + bytes([0xD4, 2]) + b"fu=1" + bytes([0xD1, 251]) + b"C"
        self.assertEqual(coap.encode(m), good)
        saved = coap.EXT8_BASE
        try:
            coap.EXT8_BASE = 12
            self.assertNotEqual(coap.encode(m), good)
            bad = cross_check(m)
            self.assertTrue(bad, "the oracle did not notice the faulty encoder")   # differs or is refused
            self.assertNotEqual(coap.decode(good).options, m.options)     # decoder shares the fault
        finally:
            coap.EXT8_BASE = saved
        self.assertEqual(cross_check(m), [])

    def test_block_values(self):
        self.assertEqual(coap.block_value(0, True, 6), 0x0E)
        self.assertEqual(coap.block_parse(0x0E), (0, True, 1024))
        self.assertEqual(coap.block_parse(coap.block_value(3, False, 6)), (3, False, 1024))
        self.assertEqual(coap.szx_for(1024), 6)
        self.assertEqual(coap.szx_for(16), 0)
        with self.assertRaises(ValueError):
            coap.szx_for(1000)

    def test_decode_rejects_garbage(self):
        for bad in (b"", b"\x40\x01", b"\x00\x01\x00\x01", b"\x49\x01\x00\x01", b"\x40\x01\x00\x01\xff",
                    b"\x40\x01\x00\x01\xf1x"):
            with self.assertRaises(coap.CoAPFormatError):
                coap.decode(bad)

    def test_rsc_both_encodings(self):
        a = coap.Message().add(coap.OM2M_RSC, 2001)
        self.assertEqual(pb.coap_rsc(a), 2001)
        b = coap.Message()
        b.options.append((coap.OM2M_RSC, b"4103"))
        self.assertEqual(pb.coap_rsc(b), 4103)


class FakeCoapServer:
    """UDP CoAP server on a kernel-chosen port: Block1 uploads answered 2.31 until the last block, every response
    body served in 16-byte Block2 blocks. Records each request it receives."""

    def __init__(self, body: bytes):
        self.body = body
        self.reqs: list[coap.Message] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                d, a = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            m = coap.decode(d)
            self.reqs.append(m)
            rep = coap.Message(mtype=coap.ACK, mid=m.mid, token=m.token)
            b1 = m.get_uint(coap.BLOCK1)
            if b1 is not None and coap.block_parse(b1)[1]:
                rep.code = coap.CONTINUE
                rep.add(coap.BLOCK1, b1)
                self.sock.sendto(coap.encode(rep), a)
                continue
            b2 = m.get_uint(coap.BLOCK2)
            num = coap.block_parse(b2)[0] if b2 is not None else 0
            rep.code = coap.CREATED if m.code == coap.POST else coap.CONTENT
            rep.add(coap.OM2M_RSC, 2001 if m.code == coap.POST else 2000)
            rep.add(coap.BLOCK2, coap.block_value(num, (num + 1) * 16 < len(self.body), 0))
            rep.payload = self.body[num * 16:(num + 1) * 16]
            self.sock.sendto(coap.encode(rep), a)

    def close(self):
        self._stop = True
        time.sleep(0.25)
        self.sock.close()


class CoapBlock2FollowUps(unittest.TestCase):
    """RFC 7959 2.4: a Block2 follow-up is the same request (same options) plus Block2. The record of 2026-11-21
    03:35Z was made before this was fixed (follow-ups carried Uri-Path + Block2 only); these tests fail on that code."""
    BODY = json.dumps({"m2m:cin": {"con": "z" * 60}}).encode()       # 85 B -> 6 blocks of 16 B

    def _check_followups(self, srv: FakeCoapServer, first_idx: int):
        first = srv.reqs[first_idx]
        drop = {coap.BLOCK1, coap.BLOCK2, coap.SIZE1, coap.CONTENT_FORMAT}
        want = [(n, v) for n, v in first.options if n not in drop]
        follow = srv.reqs[first_idx + 1:]
        self.assertTrue(follow, "no Block2 follow-up was sent")
        for i, f in enumerate(follow, start=1):
            self.assertEqual(f.code, first.code)
            self.assertEqual(f.token, first.token)
            self.assertEqual(f.payload, b"")
            self.assertEqual([(n, v) for n, v in f.options if n != coap.BLOCK2], want, f"follow-up {i}")
            self.assertEqual(coap.block_parse(f.get_uint(coap.BLOCK2))[0], i)

    def test_get_followups_repeat_the_request_options(self):
        srv = FakeCoapServer(self.BODY)
        tr = pb.CoapTransport({"csi": "id-x", "rn": "proto-p"}, srv.port, (0, 0))
        tr.open()
        try:
            r = tr.request(dict(op=2, to="proto-p/pb-ae/data/la", fr="Cbcoap1", rqi="rq1", rvi="4",
                                fc={"rcn": 1}))
            self.assertEqual((r.rsc, r.pc, r.extra["blocks2"]), (2000, json.loads(self.BODY), 6))
            self._check_followups(srv, 0)
            self.assertIn((coap.OM2M_FR, b"Cbcoap1"), srv.reqs[-1].options)
            self.assertIn((coap.URI_QUERY, b"rcn=1"), srv.reqs[-1].options)
        finally:
            tr.close()
            srv.close()

    def test_block1_post_then_block2_followups(self):
        srv = FakeCoapServer(self.BODY)
        tr = pb.CoapTransport({"csi": "id-x", "rn": "proto-p"}, srv.port, (0, 0))
        tr.open()
        try:
            r = tr.request(dict(op=1, to="proto-p/pb-ae/data", fr="Cbcoap1", rqi="rq2", rvi="4", ty=4,
                                pc={"m2m:cin": {"con": "y" * 1500}}))
            self.assertEqual((r.rsc, r.extra["blocks1"], r.extra["blocks2"]), (2001, 2, 6))
            last_b1 = max(i for i, m in enumerate(srv.reqs) if m.get_uint(coap.BLOCK1) is not None)
            self._check_followups(srv, last_b1)
            self.assertIn((coap.OM2M_TY, coap.uint_bytes(4)), srv.reqs[-1].options)
        finally:
            tr.close()
            srv.close()

    def test_helper(self):
        first = coap.Message(code=coap.POST, token=b"\x01\x02").add(coap.URI_PATH, "a").add(coap.CONTENT_FORMAT, 50)
        first.add(coap.BLOCK1, coap.block_value(2, False, 6)).add(coap.SIZE1, 3000).add(coap.OM2M_FR, "C")
        first.payload = b"x" * 10
        f = coap.block2_followup(first, 3, 6)
        self.assertEqual((f.code, f.token, f.payload), (coap.POST, b"\x01\x02", b""))
        self.assertEqual([n for n, _ in f.options], [coap.URI_PATH, coap.OM2M_FR, coap.BLOCK2])
        self.assertEqual(coap.block_parse(f.get_uint(coap.BLOCK2)), (3, False, 1024))


# ------------------------------------------------------------------------------------------------ sizes, stats
class Sizes(unittest.TestCase):
    def test_ws_frame_len_against_websockets(self):
        from websockets.frames import Frame, Opcode
        for n in (0, 1, 125, 126, 127, 4000, 65535, 65536, 70000):
            for mask in (True, False):
                raw = Frame(Opcode.TEXT, b"x" * n).serialize(mask=mask, extensions=[])
                self.assertEqual(pb.ws_frame_len(n, mask), len(raw), (n, mask))

    def test_mqtt_publish_len(self):
        # remaining = 2 + 3 + 10 = 15 -> 1 + 1 + 15
        self.assertEqual(pb.mqtt_publish_len("a/b", 10), 17)
        # remaining 127 -> 1-byte varint; 128 -> 2 bytes
        self.assertEqual(pb.mqtt_publish_len("t", 124), 1 + 1 + 127)
        self.assertEqual(pb.mqtt_publish_len("t", 125), 1 + 2 + 128)
        self.assertEqual(pb.mqtt_publish_len("t", 125, qos=1), 1 + 2 + 130)
        self.assertEqual(pb.mqtt_varint_len(16383), 2)
        self.assertEqual(pb.mqtt_varint_len(16384), 3)

    def test_mqtt_publish_len_against_paho(self):
        """paho builds the PUBLISH; capture what it writes to a socketpair."""
        import paho.mqtt.client as mqtt
        a, b = socket.socketpair()
        c = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id="t", protocol=mqtt.MQTTv311)
        c._sock = a           # noqa: SLF001 (test-only: hand paho a connected socket)
        c._state = 1          # noqa: SLF001 connected
        try:
            for topic, n in (("/oneM2M/req/Cx/id-proto-p/json", 300), ("t", 125), ("/a", 5000)):
                c.publish(topic, b"y" * n, qos=0)
                with contextlib.suppress(Exception):
                    c.loop_write()
                b.settimeout(1)
                got = b""
                want = pb.mqtt_publish_len(topic, n)
                while len(got) < want:
                    got += b.recv(65536)
                self.assertEqual(len(got), want, topic)
                self.assertEqual(got[0] & 0xF0, 0x30)
        finally:
            a.close()
            b.close()

    def test_percentile_linear(self):
        v = [1.0, 2.0, 3.0, 4.0]
        self.assertAlmostEqual(pb.percentile(v, 50), 2.5)
        self.assertAlmostEqual(pb.percentile(v, 95), 3.85)
        self.assertAlmostEqual(pb.percentile(v, 0), 1.0)
        self.assertAlmostEqual(pb.percentile(v, 100), 4.0)
        self.assertEqual(pb.percentile([5.0], 99), 5.0)
        s = pb.summarize([3, None, 1, 2])
        self.assertEqual((s["n"], s["min"], s["median"], s["max"]), (3, 1, 2, 3))
        self.assertIsNone(pb.summarize([]))

    def test_self_check(self):
        self.assertEqual(pb.self_check(100, 200, 100, 200, tls=False, exact=True), [])
        self.assertTrue(pb.self_check(100, 0, 100, 200, tls=False, exact=True))       # skipped direction
        self.assertTrue(pb.self_check(101, 200, 100, 200, tls=False, exact=True))     # one byte extra
        self.assertEqual(pb.self_check(150, 250, 100, 200, tls=False, exact=False), [])
        self.assertTrue(pb.self_check(90, 250, 100, 200, tls=False, exact=False))
        self.assertEqual(pb.self_check(122, 222, 100, 200, tls=True, exact=True), [])
        self.assertTrue(pb.self_check(121, 222, 100, 200, tls=True, exact=True))      # < one record overhead
        self.assertTrue(pb.self_check(0, 222, 100, 200, tls=True, exact=True))
        self.assertEqual(pb.self_check(None, None, 100, 200, tls=False, exact=True), [])


# ------------------------------------------------------------------------------------------------ HTTP
class Http(unittest.TestCase):
    def _server(self, replies: list[bytes]):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        got = []

        def run():
            c, _ = srv.accept()
            for rep in replies:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    buf += c.recv(65536)
                head, _, rest = buf.partition(b"\r\n\r\n")
                n = int(next((ln.split(b":")[1] for ln in head.split(b"\r\n") if ln.lower().startswith(b"content-length")), b"0"))
                while len(rest) < n:
                    rest += c.recv(65536)
                got.append(head + b"\r\n\r\n" + rest)
                c.sendall(rep)
            c.close()
            srv.close()
        threading.Thread(target=run, daemon=True).start()
        return srv.getsockname()[1], got

    def test_request_bytes_and_exact_counts(self):
        body = b'{"m2m:rsp":"ok"}'
        r1 = b"HTTP/1.1 201 CREATED\r\nX-M2M-RSC: 2001\r\nContent-Length: %d\r\n\r\n" % len(body) + body
        chunked = b"HTTP/1.1 200 OK\r\nX-M2M-RSC: 2000\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        port, got = self._server([r1, chunked])
        c = pb.HttpConn("127.0.0.1", port, None)
        c.connect()
        prim = dict(op=1, to="proto-p/ae", fr="Cx", rqi="r1", rvi="4", ty=4, pc={"m2m:cin": {"con": "x"}},
                    fc=None)
        raw = pb.http_request_bytes(prim, "127.0.0.1", port)
        st, h, b, n_out, n_in = c.roundtrip(raw, 5)
        self.assertEqual((st, h["x-m2m-rsc"], b), (201, "2001", body))
        self.assertEqual((n_out, n_in), (len(raw), len(r1)))
        self.assertIn(b"Content-Type: application/json;ty=4\r\n", raw)
        prim2 = dict(op=2, to="proto-p/ae/data", fr="Cx", rqi="r2", rvi="4", fc={"fu": 1, "lbl": ["bench:small"]})
        raw2 = pb.http_request_bytes(prim2, "127.0.0.1", port)
        self.assertTrue(raw2.startswith(b"GET /proto-p/ae/data?fu=1&lbl=bench:small HTTP/1.1\r\n"))
        self.assertNotIn(b"Content-Length", raw2)
        st, h, b, n_out, n_in = c.roundtrip(raw2, 5)
        self.assertEqual((st, b, n_in), (200, b"hello", len(chunked)))
        c.close()
        time.sleep(0.05)
        self.assertEqual(got[0], raw)


# ------------------------------------------------------------------------------------------------ proxies
class Proxies(unittest.TestCase):
    def test_tcp_proxy_counts_and_fault(self):
        echo = socket.socket()
        echo.bind(("127.0.0.1", 0))
        echo.listen(4)

        def serve():
            while True:
                try:
                    c, _ = echo.accept()
                except OSError:
                    return
                def pump(c=c):
                    while (d := c.recv(65536)):
                        c.sendall(d + b"!")            # reply one byte longer: directions must not be mixed up
                    c.close()
                threading.Thread(target=pump, daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()
        px = pb.TcpProxy("t", 0, echo.getsockname()[1])
        try:
            for fault, want in ((None, (1000, 1001)), ("skip_s2c", (1000, 0)), ("skip_c2s", (0, 1001))):
                px.fault = fault
                before = px.snap()
                s = socket.create_connection(("127.0.0.1", px.listen))
                s.sendall(b"a" * 1000)
                got = b""
                while len(got) < 1001:
                    got += s.recv(65536)
                px.settle()
                after = px.snap()
                self.assertEqual((after[0] - before[0], after[1] - before[1]), want, fault)
                self.assertEqual(after[2] - before[2], 1)                     # one connection accepted
                s.close()
        finally:
            px.close()
            echo.close()

    def test_udp_proxy_counts(self):
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        echo.bind(("127.0.0.1", 0))

        def serve():
            while True:
                try:
                    d, a = echo.recvfrom(65535)
                except OSError:
                    return
                echo.sendto(d + b"!!", a)
        threading.Thread(target=serve, daemon=True).start()
        px = pb.UdpProxy("u", 0, echo.getsockname()[1])
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("127.0.0.1", px.listen))
            s.settimeout(2)
            for n in (10, 1100, 4000):
                s.send(b"q" * n)
                self.assertEqual(len(s.recv(65535)), n + 2)
            px.settle()
            self.assertEqual(px.snap()[:2], (5110, 5116))
            s.close()
        finally:
            px.close()
            echo.close()


# ------------------------------------------------------------------------------------------------ misc logic
class Misc(unittest.TestCase):
    def test_pch_extract(self):
        rqp = {"op": 5, "rqi": "a", "pc": {"m2m:sgn": {}}}
        self.assertEqual(pb.PchPoller.extract({"m2m:rqp": rqp}), rqp)
        self.assertEqual(pb.PchPoller.extract(rqp), rqp)
        self.assertEqual(pb.PchPoller.extract({"m2m:agrp": [{"m2m:rqp": rqp}]}), rqp)
        self.assertIsNone(pb.PchPoller.extract({"m2m:cin": {}}))
        self.assertIsNone(pb.PchPoller.extract(None))

    def test_notif_marker(self):
        n = pb.Notif(0.0, "r", {"m2m:sgn": {"nev": {"rep": {"m2m:cin": {"rn": "n1x"}}, "net": 3}}})
        self.assertEqual(pb.notif_marker(n), "n1x")
        self.assertIsNone(pb.notif_marker(pb.Notif(0.0, "r", {"m2m:sgn": {"vrq": True}})))

    def test_inis(self):
        for kind in "PTCW":
            ini = pb.render_ini(pb.cse_sections(kind, "s3cret"))
            ports = [int(x) for x in __import__("re").findall(r"\b(\d{4,5})\b", ini)]
            self.assertTrue(all(39100 <= p <= 39199 for p in ports if p > 1024), (kind, ports))
            self.assertIn("networkInterface = 127.0.0.1", ini)
        t = pb.cse_sections("T", "x")
        self.assertEqual((t["http.security"]["useTLS"], t["websocket.security"]["useTLS"]), ("true", "true"))
        c = pb.cse_sections("C", "x")
        self.assertEqual((c["websocket"]["enable"], c["coap"]["enable"], c["mqtt"]["enable"]), ("false",) * 3)
        self.assertEqual(pb.cse_sections("W", "x")["http.wsgi"]["enable"], "true")
        for kind in "PTCW":
            for sec in ("websocket", "coap", "mqtt", "http"):
                self.assertEqual(pb.cse_sections(kind, "x")[sec]["listenIF"], "127.0.0.1")
        with self.assertRaises(ValueError):
            pb.render_ini({"basic.config": {"baseDirectory": "/tmp"}})
        with self.assertRaises(ValueError):
            pb.render_ini({"http": {"port": "8200"}})

    def test_child_stop_refuses_wrong_cmdline(self):
        """CONTROL for 'stop by PID after checking the command line': a child whose cmdline lacks the expected
        marker is not signalled."""
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="pbtest-", dir=str(Path(__file__).resolve().parent)))
        try:
            ch = pb.Child("sleeper", ["/bin/sleep", "30"], d, must_contain="/no/such/marker")
            with self.assertRaises(RuntimeError):
                ch.stop()
            self.assertTrue(ch.alive())
            ch.must_contain = "30"
            res = ch.stop()
            self.assertEqual(res["stopped"], "SIGINT")
            self.assertFalse(ch.alive())
        finally:
            with contextlib.suppress(Exception):
                ch.proc.kill()
            for f in d.iterdir():
                f.unlink()
            d.rmdir()

    def test_variants_and_proxies_distinct(self):
        keys = [v.key for v in pb.VARIANTS]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(set(pb.PORTS.values())), len(pb.PORTS))
        for v in pb.VARIANTS:
            if v.mech == "pch":
                self.assertNotEqual(pb.POLL_PROXY[v.proto], pb.main_proxy_key(v))


if __name__ == "__main__":
    unittest.main()
