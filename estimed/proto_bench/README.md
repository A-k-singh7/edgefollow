# proto_bench: one oneM2M workload over ACME's bindings

Measures the same oneM2M workload over http, https, ws, wss (TS-0020), mqtt (TS-0010, private mosquitto) and
coap (TS-0008, our own stdlib client) against private ACME 2026.5.3 CSEs. It records latency per operation, bytes
on the wire per direction, connection setup cost, write-to-notification delay (push vs pollingChannel) and CSE CPU
per workload, plus the controls.

## Run

    cd <directory holding proto_bench.py>
    $VENV/bin/python3 proto_bench.py --repeats 3 --rounds 4 --n-cin 40 --k-notify 12 > runlogs/full_run.log 2>&1

`$VENV` is the venv with acmecse 2026.5.3, websockets and paho (the lab's estimed venv). Paths come from the
environment: `PB_VENV` (default: the running interpreter's prefix), `PB_ACME` (default `$PB_VENV/bin/acmecse`),
`PB_OUT_DIR` (default `~/estimed-run/proto-2026-11-21`), `PB_MOSQUITTO`, `PB_OPENSSL`.

Redirect to a file; never pipe it into head/tail, because it starts background services. The record goes to
`$PB_OUT_DIR/proto_bench_<UTC>.json`, with a markdown summary beside it.

A publication copy goes next to it as `proto_bench_<UTC>_public.json` / `.md`:

    $VENV/bin/python3 make_public.py $PB_OUT_DIR/proto_bench_<UTC>.json

The copy replaces the home path in two fields with a placeholder, drops process names, and uses the current
limits wording, a recomputed summary and record-specific caveats. The raw samples are unchanged, and the
original is not modified.
`--variants http/reuse,mqtt/reuse` runs a subset. `--no-controls` skips the controls. `--keep-logs DIR` copies the
ACME and broker logs (secrets redacted, no keys) out before cleanup. `--out DIR` changes the record directory.

Offline tests (no CSE, loopback sockets on kernel-chosen ports only):

    $VENV/bin/python3 -m unittest -v test_proto_bench.py

The oracles are CoAPthon's serializer (the library inside ACME's CoAP server), websockets' frame serializer,
paho's PUBLISH bytes, the RFC 7252 Appendix A example messages and hand-computed values. Planted faults are
included: an encoder with the wrong extension base, a byte counter skipping one direction, and a child whose
command line does not match.

## What runs (all on 127.0.0.1, all ports 39110-39173, base dir /dev/shm/proto-acme, removed at the end)

| process | ports | config |
|---|---|---|
| CSE-P (ACME) | http 39110, ws 39111, coap 39112/udp | plain; MQTT client to the broker |
| CSE-T (ACME) | https 39120, wss 39121 | TLS on both (throwaway P-256 CA + leaf, IP SAN 127.0.0.1, 1 day) |
| CSE-W (ACME) | http 39113 | `[http.wsgi] enable=true` (waitress, keep-alive); ACME forbids WSGI+TLS |
| CSE-C (ACME) | http 39130; ws 39131, coap 39132 and mqtt configured but disabled | started only for the control |
| mosquitto 2.1.2 | 39150 | own conf: one loopback listener, anonymous only there, persistence off |
| counting proxies | 39140-39148, 39170-39173 | in the harness process |
| notification receivers | 39160 (http), 39161 (https), 39162/udp (coap) | in the harness process |

ACME runs one HTTP server (plain or TLS) and one WS server (ws or wss) per process, hence CSE-P and CSE-T.

The ports lie inside the host's ephemeral range (32768-60999), and other processes' client-side TIME_WAIT on one
of them blocks bind() for about 60 s. The harness waits until a port has no socket at all, starts the service,
and retries ACME up to 4 times. Every wait is recorded (`port_waits`, `start_retries`).

Startup guard: ACME aborts its own startup if an HTTP request arrives before its plugins have registered their
Flask routes ("add_url_rule ... already handled its first request"; this aborted the first full-run attempt). So
the harness sends nothing until all of a CSE's listeners exist (read from /proc), waits 2 s more, checks the log
for "Error during startup", and only then probes. `[webui] enable=false` in all inis removes the plugin that
registers routes late.

Processes are stopped by PID after their /proc cmdline is checked. Children also get PR_SET_PDEATHSIG SIGINT.
At the end the harness verifies that no listener is left on our ports, and removes /dev/shm/proto-acme (keys, inis,
logs).

## Workload (identical per binding; fresh AE + container each time)

AE create, CNT create, N CIN creates (alternating 100 B / 4000 B `con`, labels `bench:small|large`), retrieve `la`,
discovery `fu=1&lbl=bench:small`, two wrong-originator requests (expected 4103), SUB (nu = own AE-ID, so no
verification request), K notification writes, then AE delete. Variants:

- `<proto>/reuse`: one connection for the workload, where the binding has one.
- `<proto>/fresh`: a new connection per request (http, https, ws, wss).
- `http-wsgi/*`: CSE-W.
- `*-pch/reuse`: an AE with no poa and rr=false; notifications come via `<pch>/pcu` long-polling (http, https, coap).

Each repeat restarts the CSEs and the broker, runs one warm-up per variant (recorded, excluded from the
statistics), then R rounds. In each round every (variant, pass) pair runs once, in a seeded shuffled order. The
direct pass measures latency (no proxy). The proxied pass measures bytes (and checks them).

## Byte self-check

For every proxied op, the proxy's counts are compared with what the client itself put on or took off the protocol
layer: exact HTTP message bytes, WS frame sizes (RFC 6455), MQTT PUBLISH sizes, CoAP datagram sizes.

- Plaintext: the counts must be equal.
- TLS: wire >= app + 22 bytes.

The planted-fault control proves the check fires.

## Files

- `proto_bench.py`: harness.
- `coap_min.py`: CoAP codec.
- `test_proto_bench.py`: offline tests.
- `make_public.py`: publication copy plus corrected summary.
- `report_numbers.py`: compact numbers from a record.

CoAP Block2: follow-up requests repeat the first request's options plus Block2 (RFC 7959 2.4; test
`CoapBlock2FollowUps`). Records made before 2026-11-21 ~04:50 UTC used follow-ups with only Uri-Path + Block2.
Their publication copy carries a caveat with the affected byte counts.
