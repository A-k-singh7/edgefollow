# Protocol bench 2026-11-21T03:22:03.007+00:00 (ACME 2026.5.3)

Same oneM2M workload per binding; 3 repeats x 4 interleaved rounds, 40 contentInstances per workload (100 B / 4000 B con, alternating), 12 notifications per workload. Latency from the direct pass (no proxy), bytes from the proxied pass (L4 payload at a counting proxy). Host: 8 CPUs, load1 0.39-1.46. Raw record: `proto_bench_20261121T033502Z_public.json`.

## Record-specific caveats

- CoAP Block2 follow-ups in this record carried only Uri-Path + Block2; the harness was fixed afterwards (follow-ups now repeat the first request's options, RFC 7959 2.4; test CoapBlock2FollowUps). Affected numbers, all measured with the short follow-ups: coap retrieve la (4 KB, 4 follow-ups) client->CSE 255 B recorded vs ~403 B with the options; coap CIN 4 KB create (4 follow-ups) client->CSE 4565 B recorded, ~156 B low; the coap-pch poll connection for 4 KB notifications likewise. The latency of these ops was measured with the short follow-ups; the effect of the extra options on latency was not measured. CoAP ops without Block2 (100 B creates, discovery, AE/CNT create, delete) are unaffected.

## Findings (numbers from this record)

- HTTPS: ACME's built-in HTTPS server (werkzeug with TLS): CIN 100 B create 16.3 ms vs 3.8 ms over its plain HTTP server. The server closes every connection, so each request includes a TLS handshake, ~1.5 ms of the difference; ~11.1 ms more is server time before the first response byte (14.45 vs 3.36 ms after the request was sent), not explained by this run. wss on the same CSE: 2.9 ms on a kept connection, 5.3 ms with a new TLS connection per request.
- HTTP keep-alive: only with WSGI (CSE-W, waitress); not with ACME's built-in server, and a TLS-terminating proxy in front of WSGI was not tested. On loopback, CIN 100 B 3.55 ms kept vs 3.74 ms new connection per request; per-repeat medians 3.41-3.79 vs 3.56-3.82 ms, so the difference is within the run-to-run spread.
- MQTT: the first notification in a workload arrives after 47.7 ms (43.9-52.8, n=24, direct + proxied); later ones after 91.9 ms direct (p95 99.7, n=132) / 67.1 ms proxied (n=132).
- MQTT notification phase: the CIN CREATE response itself takes 48.4 ms for creates after the first notification (n=132) vs 4.1 ms for the first one and 4.0 ms for ordinary creates; the MQTT AE delete after it takes 61.0 ms vs 11.4-29.1 ms on the other bindings.
- MQTT, what is known about the stall: Nagle is on in both ACME's broker socket (paho 2.1.0 does not set TCP_NODELAY) and mosquitto's (set_tcp_nodelay not set; its default is false); our client sets TCP_NODELAY. With isolated writes (diagnostic, k=8) the CSE's response reaches the broker after 4.1 ms and its notification after 49.8 ms. A separate debug-log probe showed ACME handing the notification to its MQTT client in the same millisecond as the response (logged before it). Where the time goes is not localized and not proven.
- WebSocket opening handshakes: wss 8 of 1152 connections in measured workloads (11 of 1188 including warm-ups) got no answer for 10 s; each was retried once; ws 0 of 1152 (0 of 1188 including warm-ups). In the direct pass 4 ops and 1 connection open had a 10 s retry; they are left out of the latency cells (footnoted).
- WebSocket duplicate processing: wss/fresh 0 duplicate responses in 24 workloads, 0 ops answered 4105/5000; wss/reuse 29 duplicate responses in 24 workloads, 4 ops answered 4105/5000; ws/reuse 28 duplicate responses in 24 workloads, 4 ops answered 4105/5000; ws/fresh 0 duplicate responses in 24 workloads, 0 ops answered 4105/5000. The 8 non-OK ops in the direct pass are left out of the latency cells.
- CoAP push: 0 of 12 notifications delivered (direct pass; ACME's CoAP sender has no method for NOTIFY); pollingChannel over CoAP 15.4 ms median. CoAP 4 KB: CIN create 10.5 ms, retrieve la 5.7 ms (block-wise).

## Latency per operation (ms, median / p95 / p99 / max, n)

| variant | AE create | CNT create | CIN 100 B | CIN 4 KB | retrieve la | discovery | AE delete |
|---|---|---|---|---|---|---|---|
| wss/fresh | 5.09 / 6.19 / 6.29 / 6.31 (12) | 5.55 / 6.03 / 6.14 / 6.17 (12) | 5.34 / 6.72 / 7.13 / 7.50 (240) | 5.57 / 6.87 / 7.45 / 7.85 (238) [1] | 4.46 / 5.04 / 5.09 / 5.10 (12) | 45.04 / 48.10 / 48.87 / 49.07 (12) | 13.01 / 14.18 / 14.39 / 14.44 (11) [2] |
| https/reuse | 13.56 / 14.37 / 14.58 / 14.64 (12) | 16.27 / 17.00 / 17.38 / 17.47 (12) | 16.28 / 17.66 / 18.31 / 29.10 (240) | 16.41 / 17.64 / 18.69 / 24.01 (240) | 14.94 / 16.48 / 16.79 / 16.87 (12) | 48.20 / 50.37 / 51.40 / 51.66 (12) | 29.10 / 30.79 / 31.09 / 31.17 (12) |
| https-pch/reuse | 13.59 / 14.12 / 14.30 / 14.34 (12) | 16.08 / 16.86 / 17.27 / 17.37 (12) | - | - | - | - | 19.41 / 20.37 / 20.74 / 20.84 (12) |
| wss/reuse | 2.09 / 2.94 / 2.98 / 3.00 (12) | 2.63 / 3.72 / 3.80 / 3.82 (12) | 2.90 / 4.07 / 4.60 / 5.77 (240) | 3.08 / 4.38 / 5.42 / 7.91 (240) | 2.37 / 2.73 / 2.80 / 2.81 (12) | 42.29 / 47.72 / 49.39 / 49.81 (12) | 17.57 / 30.40 / 30.55 / 30.59 (10) [3] |
| coap-pch/reuse | 3.13 / 4.44 / 4.64 / 4.69 (12) | 3.48 / 4.39 / 4.82 / 4.93 (12) | - | - | - | - | 5.03 / 7.79 / 9.02 / 9.32 (12) |
| http-wsgi/reuse | 3.07 / 4.06 / 4.13 / 4.14 (12) | 3.39 / 4.49 / 4.56 / 4.58 (12) | 3.55 / 5.16 / 5.81 / 5.99 (240) | 3.64 / 5.45 / 5.78 / 6.78 (240) | 2.70 / 3.32 / 3.39 / 3.41 (12) | 43.41 / 49.01 / 49.44 / 49.54 (12) | 15.70 / 17.02 / 17.34 / 17.42 (12) |
| https/fresh | 16.26 / 18.69 / 19.99 / 20.31 (12) | 16.51 / 21.54 / 25.04 / 25.91 (12) | 16.28 / 17.78 / 20.21 / 22.13 (240) | 16.46 / 17.73 / 19.10 / 37.23 (240) | 14.85 / 15.46 / 15.65 / 15.70 (12) | 46.52 / 51.56 / 52.82 / 53.13 (12) | 25.49 / 26.67 / 26.85 / 26.90 (12) |
| http/fresh | 2.78 / 4.96 / 5.23 / 5.30 (12) | 3.57 / 4.23 / 4.23 / 4.23 (12) | 3.89 / 5.58 / 6.39 / 6.86 (240) | 4.00 / 5.53 / 7.83 / 10.48 (240) | 3.46 / 4.35 / 4.69 / 4.78 (12) | 42.46 / 54.03 / 59.70 / 61.11 (12) | 10.13 / 15.33 / 17.25 / 17.73 (12) |
| http/reuse | 3.21 / 4.74 / 4.79 / 4.80 (12) | 3.60 / 3.97 / 4.09 / 4.12 (12) | 3.83 / 5.65 / 6.22 / 6.97 (240) | 3.96 / 5.67 / 6.05 / 6.45 (240) | 3.08 / 3.92 / 3.98 / 3.99 (12) | 41.52 / 44.78 / 45.58 / 45.78 (12) | 16.37 / 18.45 / 18.58 / 18.61 (12) |
| http-wsgi/fresh | 2.91 / 4.69 / 5.13 / 5.25 (12) | 3.65 / 4.59 / 4.80 / 4.85 (12) | 3.74 / 5.08 / 5.58 / 5.71 (240) | 3.78 / 5.24 / 5.68 / 7.85 (240) | 2.86 / 3.51 / 3.53 / 3.54 (12) | 43.73 / 48.79 / 49.85 / 50.12 (12) | 10.52 / 12.51 / 12.60 / 12.62 (12) |
| ws/reuse | 2.16 / 2.79 / 2.79 / 2.79 (12) | 2.68 / 3.01 / 3.08 / 3.10 (12) | 2.90 / 3.77 / 4.63 / 6.45 (240) | 3.12 / 4.01 / 4.52 / 5.76 (240) | 2.28 / 2.81 / 2.89 / 2.90 (12) | 39.26 / 42.73 / 43.03 / 43.11 (12) | 16.55 / 26.93 / 29.27 / 29.85 (10) [4] |
| coap/reuse | 2.98 / 4.33 / 4.40 / 4.42 (12) | 3.52 / 4.29 / 4.55 / 4.61 (12) | 2.90 / 4.02 / 4.48 / 5.21 (240) | 10.49 / 12.68 / 13.74 / 15.31 (240) | 5.66 / 7.37 / 7.51 / 7.54 (12) | 42.56 / 49.93 / 51.56 / 51.96 (12) | 11.36 / 14.03 / 15.57 / 15.95 (12) |
| mqtt/reuse | 3.00 / 3.32 / 3.43 / 3.46 (12) | 3.80 / 4.71 / 4.78 / 4.80 (12) | 4.00 / 5.21 / 5.73 / 6.09 (240) | 4.18 / 5.36 / 5.93 / 6.28 (240) | 3.14 / 4.37 / 4.93 / 5.07 (12) | 43.00 / 48.39 / 48.63 / 48.69 (12) | 61.01 / 68.10 / 68.32 / 68.38 (12) |
| http-pch/reuse | 2.66 / 3.42 / 3.60 / 3.64 (12) | 3.88 / 5.81 / 6.80 / 7.04 (12) | - | - | - | - | 5.35 / 7.79 / 9.33 / 9.71 (12) |
| ws/fresh | 3.53 / 5.80 / 7.10 / 7.43 (12) | 3.71 / 4.54 / 4.65 / 4.67 (12) | 3.53 / 4.63 / 5.11 / 6.33 (240) | 3.63 / 4.92 / 5.27 / 5.79 (240) | 2.57 / 3.52 / 4.19 / 4.35 (12) | 37.87 / 44.18 / 44.70 / 44.83 (12) | 10.87 / 12.59 / 12.69 / 12.72 (12) |

Cells with n=12 (one sample per workload) have p95/p99 interpolated between the two largest values (linear interpolation); read them as 'near the max'. The retrieve la column is the 4 KB instance. OK responses only; errors and retried handshakes are footnoted.
[1] wss/fresh cin_create[large]: excluding 2 op(s) whose WebSocket opening handshake got no answer for 10 s
[2] wss/fresh ae_delete: excluding 1 op(s) whose WebSocket opening handshake got no answer for 10 s
[3] wss/reuse ae_delete: excluding 2 op(s) answered with an error (4105/5000, duplicate processing)
[4] ws/reuse ae_delete: excluding 2 op(s) answered with an error (4105/5000, duplicate processing)

## Bytes on the wire per operation (median, client->CSE / CSE->client; connections opened)

| variant | open (setup) | AE create | CIN 100 B | CIN 4 KB | retrieve la | discovery | notify (main conn) | notify leg / poll conn |
|---|---|---|---|---|---|---|---|---|
| wss/fresh | - | 2296 / 3159 (1c) | 2381 / 3243 (1c) | 6281 / 7144 (1c) | 2204 / 7144 (1c) | 2239 / 3830 (1c) | - | - |
| https/reuse | 1738 / 2418 (1c) | 340 / 631 | 2152 / 3116 (1c) | 6053 / 7018 (1c) | 1931 / 7013 (1c) | 1949 / 3738 (1c) | 2169 / 3111 (1c) | 2601 / 2615 (CSE->rcv / rcv->CSE, small) |
| https-pch/reuse | 1738 / 2418 (1c) | 306 / 596 | - | - | - | - | 2169 / 3110 (1c) | 4010 / 6010 (poll conn, small) |
| wss/reuse | 2021 / 2680 (1c) | 221 / 453 | 306 / 537 | 4206 / 4438 | 129 / 4438 | 164 / 1124 | 432 / 1133 | - |
| coap-pch/reuse | 0 / 0 | 138 / 320 (1c) | - | - | - | - | 263 / 419 | 255 / 659 (poll conn, small) |
| http-wsgi/reuse | 0 / 0 (1c) | 315 / 540 | 390 / 611 | 4291 / 4513 | 169 / 4508 | 187 / 1213 | 407 / 606 | 804 / 151 (CSE->rcv / rcv->CSE, small) |
| https/fresh | - | 2078 / 3049 (1c) | 2152 / 3116 (1c) | 6053 / 7018 (1c) | 1931 / 7013 (1c) | 1949 / 3762 (1c) | - | - |
| http/fresh | - | 315 / 583 (1c) | 390 / 654 (1c) | 4291 / 4556 (1c) | 169 / 4551 (1c) | 187 / 1256 (1c) | - | - |
| http/reuse | 0 / 0 (1c) | 315 / 583 | 390 / 654 (1c) | 4291 / 4556 (1c) | 169 / 4551 (1c) | 187 / 1256 (1c) | 407 / 649 (1c) | 804 / 151 (CSE->rcv / rcv->CSE, small) |
| http-wsgi/fresh | - | 315 / 540 (1c) | 390 / 611 (1c) | 4291 / 4513 (1c) | 169 / 4508 (1c) | 187 / 1213 (1c) | - | - |
| ws/reuse | 260 / 240 (1c) | 197 / 427 | 282 / 514 | 4182 / 4415 | 105 / 4415 | 140 / 1081 | 385 / 1087 | - |
| coap/reuse | 0 / 0 | 170 / 354 (1c) | 246 / 425 | 4565 / 4616 | 255 / 4583 | 98 / 1032 | 263 / 420 | 0 / 0 (CSE->rcv / rcv->CSE, small) |
| mqtt/reuse | 126 / 10 (1c) | 250 / 489 | 325 / 560 | 4225 / 4461 | 150 / 4461 | 183 / 1167 | 471 / 1178 | - |
| http-pch/reuse | 0 / 0 (1c) | 282 / 549 | - | - | - | - | 407 / 648 (1c) | 485 / 1106 (poll conn, small) |
| ws/fresh | - | 465 / 671 (1c) | 550 / 758 (1c) | 4450 / 4659 (1c) | 373 / 4659 (1c) | 408 / 1325 (1c) | - | - |

## Connection setup (ms, median / p95; from the successful attempt)

| variant | measure | median | p95 | n |
|---|---|---|---|---|
| wss/fresh | per_op.close_s | 1.218 | 1.561 | 564 |
| wss/fresh | per_op.tcp_s | 0.116 | 0.211 | 564 |
| wss/fresh | per_op.tls_s | 1.643 | 2.140 | 564 |
| wss/fresh | per_op.ws_upgrade_s | 0.902 | 1.092 | 564 |
| https/reuse | open.tcp_s | 0.105 | 0.147 | 12 |
| https/reuse | open.tls_s | 1.696 | 2.103 | 12 |
| https/reuse | per_op.tcp_s | 0.089 | 0.154 | 564 |
| https/reuse | per_op.tls_s | 1.525 | 2.084 | 564 |
| https-pch/reuse | open.tcp_s | 0.101 | 0.158 | 12 |
| https-pch/reuse | open.tls_s | 1.704 | 2.153 | 12 |
| https-pch/reuse | per_op.tcp_s | 0.085 | 0.154 | 48 |
| https-pch/reuse | per_op.tls_s | 1.530 | 2.110 | 48 |
| wss/reuse | open.tcp_s | 0.131 | 0.181 | 12 |
| wss/reuse | open.tls_s | 1.785 | 2.056 | 12 |
| wss/reuse | open.ws_upgrade_s | 0.987 | 1.155 | 12 |
| http-wsgi/reuse | open.tcp_s | 0.120 | 0.155 | 12 |
| https/fresh | per_op.tcp_s | 0.092 | 0.155 | 564 |
| https/fresh | per_op.tls_s | 1.542 | 2.160 | 564 |
| http/fresh | per_op.tcp_s | 0.110 | 0.160 | 564 |
| http/reuse | open.tcp_s | 0.109 | 0.145 | 12 |
| http/reuse | per_op.tcp_s | 0.110 | 0.156 | 564 |
| http-wsgi/fresh | per_op.tcp_s | 0.098 | 0.155 | 564 |
| ws/reuse | open.tcp_s | 0.103 | 0.132 | 12 |
| ws/reuse | open.ws_upgrade_s | 1.004 | 2.361 | 12 |
| mqtt/reuse | open.mqtt_connect_s | 0.741 | 0.846 | 12 |
| mqtt/reuse | open.mqtt_subscribe_s | 0.372 | 0.476 | 12 |
| mqtt/reuse | open.tcp_s | 0.120 | 0.195 | 12 |
| http-pch/reuse | open.tcp_s | 0.109 | 0.166 | 12 |
| http-pch/reuse | per_op.tcp_s | 0.118 | 0.170 | 48 |
| ws/fresh | per_op.close_s | 1.066 | 1.392 | 564 |
| ws/fresh | per_op.tcp_s | 0.107 | 0.202 | 564 |
| ws/fresh | per_op.ws_upgrade_s | 0.788 | 1.213 | 564 |

## Write-to-notification delay (ms, from sending the CIN CREATE to the notification in our code)

| variant | via | delivered / attempted (direct) | first in workload, median (min-max, n; direct+proxied) | later, direct: median / p95 (n) | later, proxied: median | CIN response in notify phase, direct: first / later | all, direct: median / p95 / p99 / max |
|---|---|---|---|---|---|---|---|
| https/reuse | http-receiver | 144 / 144 | 17.95 (16.22-21.88, 24) | 17.98 / 20.88 (132) | 19.44 | 17.07 / 18.09 | 17.92 / 20.76 / 25.64 / 28.87 |
| https-pch/reuse | https-pch | 144 / 144 | 12.43 (12.13-18.17, 24) | 23.89 / 25.04 (132) | 23.84 | 17.52 / 19.01 | 23.78 / 25.00 / 25.81 / 29.78 |
| wss/reuse | ws-inband | 144 / 144 (2 of the creates answered 4105) | 3.87 (3.58-5.69, 24) | 4.61 / 9.12 (132) | 4.65 | 2.59 / 3.05 | 4.46 / 9.04 / 10.54 / 11.86 |
| coap-pch/reuse | coap-pch | 144 / 144 | 14.64 (7.19-15.80, 24) | 15.62 / 18.84 (132) | 16.10 | 3.43 / 11.61 | 15.43 / 18.73 / 22.55 / 65.60 |
| http-wsgi/reuse | http-receiver | 144 / 144 | 6.63 (4.91-8.96, 24) | 6.55 / 7.98 (132) | 7.10 | 3.78 / 3.89 | 6.51 / 8.00 / 8.94 / 9.01 |
| http/reuse | http-receiver | 144 / 144 | 7.16 (5.16-10.25, 24) | 6.81 / 8.12 (132) | 7.60 | 3.17 / 4.50 | 6.80 / 8.08 / 8.90 / 9.45 |
| ws/reuse | ws-inband | 144 / 144 (2 of the creates answered 4105) | 4.10 (3.14-5.51, 24) | 4.53 / 7.71 (132) | 4.62 | 2.76 / 3.06 | 4.47 / 7.68 / 9.40 / 9.74 |
| coap/reuse | - | 0 / 12 | - | - | - | 3.34 / - | - / - / - / - |
| mqtt/reuse | mqtt-broker | 144 / 144 | 47.73 (43.86-52.77, 24) | 91.87 / 99.73 (132) | 67.11 | 4.07 / 48.43 | 91.85 / 99.68 / 99.90 / 99.92 |
| http-pch/reuse | http-pch | 144 / 144 | 14.71 (6.55-15.94, 24) | 12.07 / 15.56 (132) | 14.59 | 4.62 / 4.59 | 12.09 / 15.57 / 16.99 / 17.85 |

## MQTT timing in detail (ms)

| what | median | p95 | min | max | n |
|---|---|---|---|---|---|
| first notification in a workload (direct + proxied) | 47.73 | 51.03 | 43.86 | 52.77 | 24 |
| later notifications, direct | 91.87 | 99.73 | 87.60 | 99.92 | 132 |
| later notifications, proxied | 67.11 | 72.96 | 26.18 | 79.00 | 132 |
| CIN CREATE response, first create of the notify phase (direct) | 4.07 | 5.28 | 2.67 | 5.72 | 12 |
| CIN CREATE response, later creates of the notify phase (direct) | 48.43 | 52.05 | 46.31 | 53.29 | 132 |
| CIN 100 B CREATE response outside the notify phase (direct) | 4.00 | 5.21 | 3.04 | 6.09 | 240 |
| AE delete after the notify phase (direct) | 61.01 | 68.10 | 54.72 | 68.38 | 12 |

## Stability (CIN 100 B create, median ms per repeat; CSE CPU per workload)

| variant | per repeat | max/min | load1 range | host busy | CSE CPU ms / workload (median) |
|---|---|---|---|---|---|
| wss/fresh | 5.26, 5.39, 5.41 | 1.03 | 0.75-1.38 | 6%-24% | 330 |
| https/reuse | 16.33, 16.17, 16.34 | 1.01 | 0.65-1.35 | 11%-17% | 530 |
| https-pch/reuse |  | - | 0.75-1.45 | 7%-14% | 205 |
| wss/reuse | 2.87, 2.92, 2.91 | 1.02 | 0.56-1.46 | 5%-37% | 275 |
| coap-pch/reuse |  | - | 0.56-1.39 | 11%-27% | 205 |
| http-wsgi/reuse | 3.79, 3.52, 3.41 | 1.11 | 0.71-1.33 | 15%-28% | 305 |
| https/fresh | 16.30, 16.13, 16.34 | 1.01 | 0.39-1.46 | 10%-15% | 310 |
| http/fresh | 3.95, 3.82, 4.21 | 1.10 | 0.39-1.45 | 14%-28% | 240 |
| http/reuse | 3.84, 3.79, 3.94 | 1.04 | 0.82-1.39 | 15%-25% | 335 |
| http-wsgi/fresh | 3.67, 3.82, 3.56 | 1.07 | 0.82-1.46 | 15%-23% | 225 |
| ws/reuse | 2.86, 2.92, 2.90 | 1.02 | 0.39-1.23 | 15%-21% | 270 |
| coap/reuse | 2.86, 2.87, 2.96 | 1.03 | 0.75-1.42 | 7%-12% | 420 |
| mqtt/reuse | 4.09, 3.93, 3.97 | 1.04 | 0.56-1.41 | 7%-15% | 395 |
| http-pch/reuse |  | - | 0.56-1.39 | 9%-21% | 150 |
| ws/fresh | 3.66, 3.36, 3.49 | 1.09 | 0.60-1.45 | 17%-29% | 260 |

CSE CPU compares only variants with the same operations: the reuse variants include the subscription and 12 notifications; fresh variants have no notification phase; pollingChannel variants have no CIN/la/discovery phase (not comparable); coap/reuse has one push probe instead of the notifications.

## HTTP response timing, CIN 100 B create (ms, median / p95): time from sending the request to the first response byte, largest gap between response chunks, recv chunks

| variant | total | to first byte | largest gap | chunks |
|---|---|---|---|---|
| https/reuse | 16.28 | 14.45 / 15.49 | 0.05 / 0.09 | 2 |
| http-wsgi/reuse | 3.55 | 3.20 / 4.24 | 0.07 / 1.23 | 2 |
| https/fresh | 16.28 | 14.52 / 15.46 | 0.06 / 0.11 | 2 |
| http/fresh | 3.89 | 3.32 / 4.41 | 0.06 / 1.37 | 2 |
| http/reuse | 3.83 | 3.36 / 4.31 | 0.05 / 1.38 | 2 |
| http-wsgi/fresh | 3.74 | 3.14 / 4.05 | 0.06 / 1.25 | 2 |

## WebSocket opening handshakes with no answer for 10 s (each retried once)

| variant | connections (measured) | no answer | connections incl. warm-ups | no answer | direct-pass ops / opens retried | example |
|---|---|---|---|---|---|---|
| wss/fresh | 1128 | 7 | 1161 | 9 | 4 / 0 | InvalidMessage: did not receive a valid HTTP response after 10.0015 s |
| wss/reuse | 24 | 1 | 27 | 2 | 0 / 1 | InvalidMessage: did not receive a valid HTTP response after 10.001 s |
| ws/reuse | 24 | 0 | 27 | 0 | 0 / 0 | - |
| ws/fresh | 1128 | 0 | 1161 | 0 | 0 / 0 | - |

## WebSocket duplicate responses (same rqi answered twice)

| variant | workloads | duplicate responses | ops with rsc 4105/5000 |
|---|---|---|---|
| wss/fresh | 24 | 0 | 0 |
| wss/reuse | 24 | 29 | 4 |
| ws/reuse | 24 | 28 | 4 |
| ws/fresh | 24 | 0 | 0 |

## Controls

- **wrong_ca_rejected_by_client**: pass = True
- **mqtt_wrong_topic_and_originator**: pass = True
- **planted_byte_counter_fault**: pass = True
- **disabled_binding_refuses**: pass = True
- **wrong originator, every binding**: wss/fresh [4103]; https/reuse [4103]; wss/reuse [4103]; http-wsgi/reuse [4103]; https/fresh [4103]; http/fresh [4103]; http/reuse [4103]; http-wsgi/fresh [4103]; ws/reuse [4103]; coap/reuse [4103]; mqtt/reuse [4103]; ws/fresh [4103] -> all 4103: True
- **byte self-check on all proxied samples**: exact equality 5004 (flagged 0); lower bound 3336 (TLS: wire >= app + 22 B, 2772; new ws connection incl. upgrade/close, 564; flagged 0); not checked 120 (connect samples, no app bytes)

## Operations that did not return the expected result

- wss/reuse: 4 e.g. [['notify', '4105', 'frame', 'None'], ['ae_delete', '5000', 'frame', 'None'], ['notify', '4105', 'frame', 'None']]
- ws/reuse: 4 e.g. [['notify', '4105', 'frame', 'None'], ['notify', '4105', 'frame', 'None'], ['ae_delete', '5000', 'frame', 'None']]
- coap/reuse: 24 e.g. [['notify', '2001', '2.01', 'None'], ['notify', '2001', '2.01', 'None'], ['notify', '2001', '2.01', 'None']]

## Diagnostic: our HTTP client vs `requests` (GET CSEBase, ms median / p95)

| CSE | ours, new connection | requests, new connection | requests.Session |
|---|---|---|---|
| CSE-P http | 1.54 / 1.87 | 2.60 / 3.30 | 2.37 / 2.76 |
| CSE-T https | 13.94 / 15.00 | 15.60 / 17.63 | 15.41 / 16.72 |
| CSE-W http | 1.41 / 1.94 | 2.47 / 3.11 | 2.16 / 2.66 |

## Diagnostic: MQTT path with isolated writes (median ms from sending the CIN CREATE, k=8)

| request at broker | response at broker | response at client | notification at broker | notification at client |
|---|---|---|---|---|
| 0.36 | 4.08 | 3.90 | 49.76 | 49.48 |

'at broker' = when the broker delivered the PUBLISH to a sniffer subscribed to /oneM2M/#. These timestamps do not say where between ACME and the broker the time is spent.

## Not measured / limits

- HTTP: ACME's built-in HTTP server (werkzeug 3.1.8 development server, used when [http.wsgi] is off) sends 'Connection: close' on every response, so http/reuse and https/reuse open a new TCP (and TLS) connection for every request. Keep-alive HTTP was measured on CSE-W (same ACME, [http.wsgi] enable=true, waitress). ACME refuses WSGI together with TLS, so HTTPS keep-alive is not available with ACME's built-in server; a TLS-terminating proxy in front of WSGI was not tested.
- CoAP push: a notification to a coap:// poa is never sent (ACME logs 'Creating new CoAP client' and nothing after; its CoAP sender maps only CREATE/RETRIEVE/UPDATE/DELETE to methods, CoAPthonTools.operationsMethodsMap has no NOTIFY). coap/reuse therefore has no push numbers; the pollingChannel over CoAP (coap-pch) works.
- WebSocket: ACME's receive loop hands each frame to a worker as `lambda: _handleReceivedMessage(websocket, message, ...)`; `message` is read when the worker runs, so two frames arriving back-to-back can be processed as the second frame twice (and the first lost). Our client answers each pushed notification at once and then sends its next request, which triggers this; duplicate responses are counted (ws_unmatched_responses), not hidden.
- ACME 2026.5.3 runs one HTTP server (plain OR TLS) and one WS server (ws OR wss) per process, so http/ws/mqtt/coap ran on CSE-P and https/wss on CSE-T: same version, same ini apart from the TLS flags and IDs/ports.
- Bytes are L4 payload (TCP stream / UDP datagram) at a counting proxy; IP/TCP/UDP headers, TCP ACKs and the TCP handshake segments are not included.
- MQTT bytes are the client<->broker leg only; the broker relays each PUBLISH to the CSE over a second connection (CSE<->broker leg, not counted). QoS 0 both ways (ACME's default); no MQTT TLS.
- MQTT timing: Nagle is on in ACME's broker socket (paho 2.1.0 does not set TCP_NODELAY) and in mosquitto's (set_tcp_nodelay not set in our conf; mosquitto's default is false); our MQTT client sets TCP_NODELAY. The extra time on MQTT notifications and on notify-phase and AE-delete responses is reported as measured; where it arises between ACME, its paho client and the broker is not localized, and its cause is not proven.
- CoAP without DTLS (ACME's client side says 'CoAP security is not yet supported'; no DTLS client in the stdlib). No CoAP fresh/reuse distinction (connectionless).
- ws/wss: our client does not negotiate permessage-deflate and sends no keepalive pings; ACME's server would accept deflate, which would change ws byte counts.
- fresh mode (one connection per request) was run for http/https/ws/wss; MQTT and CoAP have no per-request connection in their normal use. Notifications were measured in reuse mode only.
- ACME startup race (observed 2026-11-21): an HTTP request that reaches a starting CSE before its plugins have registered their Flask routes aborts the startup ('add_url_rule ... It has already handled its first request'). The harness sends nothing until all of the CSE's listeners exist + 2 s, and records every start retry (start_retries); the first full-run attempt was aborted by this and is kept as *_ABORTED_startup_race.json.
- Latency of the proxied pass is not used for the latency tables (the proxy runs in the client's process); the direct pass has no proxy. Proxied notification delays are shown separately where they differ.
- Another agent was running lab tests on the same host during this run; both disturb each other's timing. load1 and host CPU busy fraction are recorded per workload.
