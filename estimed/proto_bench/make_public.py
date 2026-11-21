"""Write a publication copy of a proto_bench record and its corrected summary, next to the original.

The raw samples (workloads, controls, diagnostics, config, versions) are copied unchanged, except:
  - software.python_exe and stops[].cmdline_checked: the home path is replaced by <venv>/<home>
  - host.top_cpu_start / top_cpu_end: process names dropped, only the CPU percentages kept
  - limits: the current wording from proto_bench.LIMITS; summary: recomputed by the current build_summary
  - caveats: record-specific notes (e.g. CoAP Block2 follow-ups of records made before that fix)
The original record is not modified. Usage:  python3 make_public.py <record.json>
"""
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import coap_min as coap  # noqa: E402
import proto_bench as pb  # noqa: E402


def scrub_path(x: str) -> str:
    x = re.sub(r"/home/[^/\s]+/[^\s]*?/bin/", "<venv>/bin/", x)
    return re.sub(r"/home/[^/\s]+", "<home>", x)


def coap_followup_caveat(rec: dict) -> list[str]:
    """For records whose CoAP Block2 follow-ups carried only Uri-Path + Block2: how many bytes the follow-ups
    would have had with the first request's options (computed from the record's own IDs)."""
    if rec.get("coap_block2_followups"):
        return []
    tr = pb.CoapTransport(pb.CSE["P"], 0, (0, 0))

    def short_by(prim: dict, nfollow: int) -> int:
        tok = b"\x00\x01\x02\x03"
        base = tr._base_msg(prim, tok)
        old = coap.Message(code=base.code, token=tok, options=[(n, v) for n, v in base.options if n == coap.URI_PATH])
        d = 0
        for num in range(1, nfollow + 1):
            o = coap.Message(code=old.code, token=tok, options=list(old.options)).add(coap.BLOCK2, coap.block_value(num, False, 6))
            d += len(coap.encode(coap.block2_followup(base, num, 6))) - len(coap.encode(o))
        return d

    out = []
    cw = [w for w in rec["workloads"] if w["variant"] == "coap/reuse" and w["proxied"] and not w.get("warmup")]
    if cw:
        w = cw[0]
        ae = "pb-" + w["origin"][1:]
        la = [s for s in w["samples"] if s["op"] == "retrieve_la"]
        cl = sorted(s["wc"] for x in cw for s in x["samples"] if s["op"] == "cin_create" and s.get("size") == "large")
        nf_la = (la[0].get("blocks2") or 1) - 1 if la else 4
        nf_cl = max((s.get("blocks2") or 1) for x in cw for s in x["samples"] if s["op"] == "cin_create") - 1
        d_la = short_by(dict(op=2, to=f"proto-p/{ae}/data/la", fr=w["origin"], rqi="rq" + "0" * 12, rvi=pb.RVI), nf_la)
        d_cl = short_by(dict(op=1, to=f"proto-p/{ae}/data", fr=w["origin"], rqi="rq" + "0" * 12, rvi=pb.RVI, ty=4), nf_cl)
        out.append(f"CoAP Block2 follow-ups in this record carried only Uri-Path + Block2; the harness was fixed afterwards "
                   f"(follow-ups now repeat the first request's options, RFC 7959 2.4; test CoapBlock2FollowUps). "
                   f"Affected numbers, all measured with the short follow-ups: coap retrieve la (4 KB, {nf_la} follow-ups) "
                   f"client->CSE {la[0]['wc'] if la else '?'} B recorded vs ~{(la[0]['wc'] + d_la) if la else '?'} B with "
                   f"the options; coap CIN 4 KB create ({nf_cl} follow-ups) client->CSE {cl[len(cl) // 2] if cl else '?'} B "
                   f"recorded, ~{d_cl} B low; the coap-pch poll connection for 4 KB notifications likewise. The latency "
                   f"of these ops was measured with the short follow-ups; the effect of the extra options on latency "
                   f"was not measured. CoAP ops without Block2 (100 B creates, discovery, AE/CNT create, delete) are unaffected.")
    return out


def main(src: str) -> int:
    src_p = Path(src)
    raw = src_p.read_bytes()
    rec = json.loads(raw)
    pub = copy.deepcopy(rec)
    pub["software"]["python_exe"] = "<venv>/bin/python3"
    for st in pub.get("stops", []):
        if "cmdline_checked" in st:
            st["cmdline_checked"] = scrub_path(st["cmdline_checked"])
    for k in ("top_cpu_start", "top_cpu_end"):
        if k in pub.get("host", {}):
            pub["host"][k] = [float(x.split()[0]) for x in pub["host"][k] if x.split()]
    pub["limits"] = list(pb.LIMITS)
    pub["caveats"] = coap_followup_caveat(rec)
    pub["summary"] = pb.build_summary(pub["workloads"])
    name = src_p.name.replace(".json", "_public.json")
    pub["_json_name"] = name
    pub["publication_note"] = dict(
        source=src_p.name, source_sha256=hashlib.sha256(raw).hexdigest(),
        scrubbed=["software.python_exe", "stops[].cmdline_checked (home path)", "host.top_cpu_start/top_cpu_end (process names)"],
        replaced=["limits (current wording)", "summary (recomputed from the same raw samples)", "caveats (added)"],
        unchanged="workloads (every raw sample), controls, diagnostics, config, ports, params, software versions, repeats")
    home_user = Path.home().name
    bad = []

    def walk(o, p_=""):
        if isinstance(o, dict):
            for k_, v in o.items():
                walk(v, f"{p_}.{k_}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{p_}[{i}]")
        elif isinstance(o, str) and ("/home/" in o or re.search(rf"\b{re.escape(home_user)}\b", o)):
            bad.append(p_)
    walk(pub)
    if bad:
        raise SystemExit(f"not scrubbed: {bad[:10]}")
    out = src_p.with_name(name)
    out.write_text(json.dumps(pub, separators=(",", ":"), default=str))
    md = pb.summary_markdown(pub)
    if "/home/" in md or re.search(rf"\b{re.escape(home_user)}\b", md):
        raise SystemExit("summary markdown carries a home path / user name")
    out.with_suffix(".md").write_text(md)
    assert hashlib.sha256(src_p.read_bytes()).hexdigest() == pub["publication_note"]["source_sha256"]
    print(out, out.with_suffix(".md"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
