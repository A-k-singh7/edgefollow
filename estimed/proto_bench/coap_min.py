"""Minimal CoAP (RFC 7252) message codec + block-wise (RFC 7959) helpers, stdlib only.

Written for proto_bench.py's CoAP transport against ACME 2026.5.3 (CoAPthon server). Only what the
oneM2M CoAP binding (TS-0008) needs: header, token, options (delta/length with 13/14 extensions),
payload marker, uint/string option values, Block1/Block2 values.

The oneM2M option numbers are the ones ACME registers (acmecse/helpers/CoAPthonTools.py,
registerOneM2MOptions), not taken from memory of TS-0008.
"""
from __future__ import annotations

import dataclasses
import struct

VERSION = 1
CON, NON, ACK, RST = 0, 1, 2, 3
TYPE_NAMES = {CON: "CON", NON: "NON", ACK: "ACK", RST: "RST"}

# Codes as (class << 5) | detail
GET, POST, PUT, DELETE = 1, 2, 3, 4
EMPTY = 0


def code(cls: int, detail: int) -> int:
    return (cls << 5) | detail


def code_str(c: int) -> str:
    return f"{c >> 5}.{c & 0x1F:02d}"


CREATED, DELETED, VALID, CHANGED, CONTENT, CONTINUE = (code(2, 1), code(2, 2), code(2, 3), code(2, 4),
                                                      code(2, 5), code(2, 31))

# RFC 7252 / 7959 option numbers
URI_HOST, ETAG, OBSERVE, URI_PORT, LOCATION_PATH, URI_PATH, CONTENT_FORMAT = 3, 4, 6, 7, 8, 11, 12
MAX_AGE, URI_QUERY, ACCEPT, LOCATION_QUERY, BLOCK2, BLOCK1, SIZE2, SIZE1 = 14, 15, 17, 20, 23, 27, 28, 60
# oneM2M options as ACME 2026.5.3 registers them (CoAPthonTools.registerOneM2MOptions)
OM2M_OT, OM2M_RTURI, OM2M_TY, OM2M_RVI, OM2M_ASRI, OM2M_FR, OM2M_RQI = 259, 263, 267, 271, 275, 279, 283
OM2M_RQET, OM2M_RSET, OM2M_OET, OM2M_EC, OM2M_RSC, OM2M_GID, OM2M_VSI = 291, 295, 299, 303, 307, 311, 331
# which options carry unsigned integers (others: strings/opaque)
UINT_OPTIONS = {URI_PORT, CONTENT_FORMAT, MAX_AGE, ACCEPT, BLOCK2, BLOCK1, SIZE2, SIZE1, OBSERVE,
                OM2M_TY, OM2M_EC, OM2M_RSC}
CF_JSON = 50

PAYLOAD_MARKER = 0xFF
# extended-field bases (RFC 7252 3.1): nibble 13 -> 1 extra byte + 13, nibble 14 -> 2 extra bytes + 269
EXT8_BASE = 13
EXT16_BASE = 269


class CoAPFormatError(ValueError):
    pass


def uint_bytes(v: int) -> bytes:
    """Minimal-length big-endian unsigned integer (RFC 7252 3.2: 0 is the empty string)."""
    if v < 0:
        raise ValueError("negative uint")
    n = (v.bit_length() + 7) // 8
    return v.to_bytes(n, "big") if n else b""


def bytes_uint(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0


@dataclasses.dataclass
class Message:
    mtype: int = CON
    code: int = EMPTY
    mid: int = 0
    token: bytes = b""
    options: list[tuple[int, bytes]] = dataclasses.field(default_factory=list)   # (number, raw value)
    payload: bytes = b""

    # -- option helpers ------------------------------------------------------------------------
    def add(self, number: int, value: int | str | bytes) -> "Message":
        if isinstance(value, int):
            raw = uint_bytes(value)
        elif isinstance(value, str):
            raw = value.encode("utf-8")
        else:
            raw = bytes(value)
        self.options.append((number, raw))
        return self

    def get_all(self, number: int) -> list[bytes]:
        return [v for n, v in self.options if n == number]

    def get(self, number: int) -> bytes | None:
        vals = self.get_all(number)
        return vals[0] if vals else None

    def get_uint(self, number: int) -> int | None:
        v = self.get(number)
        return None if v is None else bytes_uint(v)

    def get_str(self, number: int) -> str | None:
        v = self.get(number)
        return None if v is None else v.decode("utf-8", "replace")


def _nibble(value: int) -> tuple[int, bytes]:
    if value < EXT8_BASE:
        return value, b""
    if value < EXT16_BASE:
        return 13, bytes([value - EXT8_BASE])
    if value < EXT16_BASE + 0x10000:
        return 14, struct.pack("!H", value - EXT16_BASE)
    raise CoAPFormatError(f"option delta/length too large: {value}")


def encode(msg: Message) -> bytes:
    if not 0 <= len(msg.token) <= 8:
        raise CoAPFormatError("token length must be 0..8")
    out = bytearray()
    out.append((VERSION << 6) | (msg.mtype << 4) | len(msg.token))
    out.append(msg.code & 0xFF)
    out += struct.pack("!H", msg.mid & 0xFFFF)
    out += msg.token
    last = 0
    # stable sort keeps the order of repeated options (Uri-Path segments, Uri-Query parts)
    for number, raw in sorted(msg.options, key=lambda o: o[0]):
        d_nib, d_ext = _nibble(number - last)
        l_nib, l_ext = _nibble(len(raw))
        out.append((d_nib << 4) | l_nib)
        out += d_ext + l_ext + raw
        last = number
    if msg.payload:
        out.append(PAYLOAD_MARKER)
        out += msg.payload
    return bytes(out)


def _read_ext(nib: int, data: bytes, i: int) -> tuple[int, int]:
    if nib < 13:
        return nib, i
    if nib == 13:
        if i + 1 > len(data):
            raise CoAPFormatError("truncated 8-bit extension")
        return data[i] + EXT8_BASE, i + 1
    if nib == 14:
        if i + 2 > len(data):
            raise CoAPFormatError("truncated 16-bit extension")
        return struct.unpack_from("!H", data, i)[0] + EXT16_BASE, i + 2
    raise CoAPFormatError("reserved nibble 15")


def decode(data: bytes) -> Message:
    if len(data) < 4:
        raise CoAPFormatError("shorter than the 4-byte header")
    b0 = data[0]
    if b0 >> 6 != VERSION:
        raise CoAPFormatError(f"version {b0 >> 6}")
    tkl = b0 & 0x0F
    if tkl > 8:
        raise CoAPFormatError("token length > 8")
    msg = Message(mtype=(b0 >> 4) & 0x03, code=data[1], mid=struct.unpack_from("!H", data, 2)[0])
    i = 4
    if i + tkl > len(data):
        raise CoAPFormatError("truncated token")
    msg.token = bytes(data[i:i + tkl])
    i += tkl
    number = 0
    while i < len(data):
        if data[i] == PAYLOAD_MARKER:
            if i + 1 >= len(data):
                raise CoAPFormatError("payload marker with empty payload")
            msg.payload = bytes(data[i + 1:])
            break
        d_nib, l_nib = data[i] >> 4, data[i] & 0x0F
        i += 1
        delta, i = _read_ext(d_nib, data, i)
        length, i = _read_ext(l_nib, data, i)
        if i + length > len(data):
            raise CoAPFormatError("truncated option value")
        number += delta
        msg.options.append((number, bytes(data[i:i + length])))
        i += length
    return msg


# -- block-wise (RFC 7959 2.2) ---------------------------------------------------------------------
def block_value(num: int, more: bool, szx: int) -> int:
    if not 0 <= szx <= 6:
        raise ValueError("szx must be 0..6")
    return (num << 4) | (int(more) << 3) | szx


def block_parse(v: int) -> tuple[int, bool, int]:
    """-> (num, more, size in bytes)"""
    return v >> 4, bool(v & 0x08), 1 << ((v & 0x07) + 4)


def szx_for(size: int) -> int:
    szx = size.bit_length() - 5
    if size != 1 << (szx + 4) or not 0 <= szx <= 6:
        raise ValueError(f"block size must be a power of two in 16..1024: {size}")
    return szx


# options that describe the request payload or its Block1 transfer: not repeated on a Block2 follow-up
_NOT_ON_FOLLOWUP = {BLOCK1, BLOCK2, SIZE1, SIZE2, CONTENT_FORMAT}


def block2_followup(first: Message, num: int, szx: int) -> Message:
    """Request for block `num` of a Block2 response (RFC 7959 2.4): the same request as the first one -- same code,
    token and options (Uri-Path, Uri-Query, Accept, the oneM2M options ...) -- without its payload and without the
    options that describe that payload (Content-Format, Block1, Size1), plus Block2(num, M=0, szx)."""
    m = Message(mtype=first.mtype, code=first.code, token=first.token,
                options=[(n, v) for n, v in first.options if n not in _NOT_ON_FOLLOWUP])
    m.add(BLOCK2, block_value(num, False, szx))
    return m


def describe(msg: Message) -> str:
    return (f"{TYPE_NAMES.get(msg.mtype, msg.mtype)} {code_str(msg.code)} mid={msg.mid} tok={msg.token.hex()} "
            f"opts={[(n, v if n not in UINT_OPTIONS else bytes_uint(v)) for n, v in msg.options]} "
            f"payload={len(msg.payload)}B")
