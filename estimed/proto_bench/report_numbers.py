"""Print the compact numbers for the hand-off report from a proto_bench record (newest by default)."""
import glob
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else sorted(
    p for p in glob.glob(str(__import__("proto_bench").OUT_DIR / "proto_bench_*.json")) if "ABORTED" not in p)[-1]
r = json.load(open(path))
s = r["summary"]
print("record", path)
print("started", r["started_utc"], "finished", r["finished_utc"], "params", r["params"]["repeats"], r["params"]["rounds"],
      r["params"]["n_cin"], r["params"]["k_notify"], "body bytes", r["params"]["body_bytes"])
print("host", r["host"]["cpu_count"], "load1", r["host"]["load1_min"], r["host"]["load1_max"], "start", r["host"]["load_start"],
      "end", r["host"]["load_end"])
print("top cpu start", r["host"]["top_cpu_start"][:5])
print("port waits", r.get("port_waits"), "retries", r.get("start_retries"))
print("tls", [ (w["variant"], w["samples"][0].get("setup", {}).get("tls_version"), w["samples"][0].get("setup", {}).get("cipher"))
       for w in r["workloads"] if w["variant"] == "https/reuse" and w["samples"] and w["samples"][0]["op"] == "connect"][:1])


def m(d, k, f="median"):
    x = (d or {}).get(k)
    return None if not x else round(x[f], 2)


print("\nLATENCY ms median/p95 (n)")
for vk, d in s["latency_ms"].items():
    cs = d.get("cin_create[small]") or {}
    print(f"{vk:16} cinS {m(d,'cin_create[small]')}/{m(d,'cin_create[small]','p95')} ({cs.get('n')})  "
          f"cinL {m(d,'cin_create[large]')}/{m(d,'cin_create[large]','p95')}  la {m(d,'retrieve_la[large]')}/{m(d,'retrieve_la[large]','p95')}  "
          f"disc {m(d,'discovery')}/{m(d,'discovery','p95')}  ae {m(d,'ae_create')}  notifyCreate {m(d,'notify[small]')}  "
          f"p99 cinS {m(d,'cin_create[small]','p99')} max {m(d,'cin_create[small]','max')}")
print("\nBYTES median c2s/s2c (conns)")
for vk, d in s["bytes"].items():
    def b(k):
        x = d.get(k)
        return "-" if not x else f"{x['c2s']:.0f}/{x['s2c']:.0f}({x.get('conns') or 0:.0f})"
    nl = d.get("notify[small]") or {}
    leg = f"leg {nl.get('leg_wc')}/{nl.get('leg_ws')}" if nl.get("leg_wc") is not None else (
        f"poll {nl.get('poll_wc')}/{nl.get('poll_ws')}" if nl.get("poll_wc") is not None else "")
    print(f"{vk:16} open {b('connect')} cinS {b('cin_create[small]')} cinL {b('cin_create[large]')} la {b('retrieve_la[large]')} "
          f"disc {b('discovery')} notifyS {b('notify[small]')} {leg}")
print("\nSETUP ms median")
for vk, d in s["setup"].items():
    print(f"{vk:16}", {k: round(v["median"], 3) for k, v in d.items() if v})
print("\nNOTIFY ms")
for vk, d in s["notify"].items():
    x = d["delay_ms"] or {}
    print(f"{vk:16} {d['via']} {d['delivered']}/{d['attempted']} med {x.get('median') and round(x['median'],2)} p95 "
          f"{x.get('p95') and round(x['p95'],2)} p99 {x.get('p99') and round(x['p99'],2)} max {x.get('max') and round(x['max'],2)} "
          f"small {(d['delay_ms_small'] or {}).get('median') and round(d['delay_ms_small']['median'],2)} large "
          f"{(d['delay_ms_large'] or {}).get('median') and round(d['delay_ms_large']['median'],2)} abandoned {d['abandoned']}")
print("\nSTABILITY")
for vk, d in s["stability"].items():
    cpu = s["cse_cpu_ms_per_workload"].get(vk) or {}
    print(f"{vk:16} per-rep {[round(v,2) for v in d['cin_small_median_ms_per_repeat'].values()]} max/min "
          f"{d['max_over_min'] and round(d['max_over_min'],3)} load1 {d['load1_range']} busy "
          f"{[round(x,2) for x in d['host_busy_range']] if d['host_busy_range'] else None} cseCPU {cpu.get('median') and round(cpu['median'])}")
print("\nHTTP timing", {k: (round(v["ttfb_ms"]["median"], 2), round(v["max_gap_ms"]["median"], 3)) for k, v in (s.get("http_response_timing") or {}).items()})
print("ws stalls", {k: (v["attempts"], v["failed"]) for k, v in (s.get("ws_connect_stalls") or {}).items()})
print("ws stall examples", [e for v in (s.get("ws_connect_stalls") or {}).values() for e in v["examples"]][:3])
print("ws dups", s.get("ws_duplicates"))
print("selfcheck flagged", {k: (v["checked"], v["flagged"]) for k, v in s["selfcheck"].items() if v["flagged"]},
      "total", sum(v["checked"] for v in s["selfcheck"].values()))
print("wrong orig", {k: (v["n"], v["rsc"]) for k, v in s["wrong_originator"].items()})
print("failures", s["failures"])
print("\nCONTROLS")
for k, v in r["controls"].items():
    print(k, json.dumps(v)[:900])
print("\nDIAG", json.dumps(r.get("diagnostics", {}).get("client_crosscheck_ms"), default=str)[:1500])
print("MQTT path", r.get("diagnostics", {}).get("mqtt_path", {}).get("median_ms"))
print("\nlog digest", [(x["rep"], {k: v[:4] for k, v in x["log_digest"].items()}) for x in r["repeats"]])
print("push ok", [x.get("push_ok_after_warmup") for x in r["repeats"]])
print("stops", [(x.get("name"), x.get("stopped")) for x in r.get("stops", [])])
print("leftover", r["leftover_listeners"], "root removed", r["root_removed"], "error", r.get("error"), r.get("interrupted"))
