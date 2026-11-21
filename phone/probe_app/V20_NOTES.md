# probe app v20 (built 2026-11-19; installed in place on both lab phones on 2026-11-19 with the same signer; a key kept
# on 2026-10-15 still signs afterwards; no stream has run on v20 yet, and the https path has never run)

APK: `phone/probe_app/build_v20/probe.apk` (gitignored), sha256
`bb2d66e9b751c1cc274e7d2d276ce675ddec11e5074b0e0c99fdb441237e2dc7`, 49,660 B.
`aapt2 dump badging`: package `org.edgefollow.probe`, `versionCode='20' versionName='20'`, targetSdk 30.
Signer (`apksigner verify --print-certs`, v3 scheme): certificate SHA-256
`49f43629df6dc199291d9b26420bbeb1aea785fda950511621342d9564f77fbf`, equal to the signer of
`build/probe.apk` (v19, sha256 `d3fb7bec…da84`) and to the digest written in V19_NOTES.md.
Built with `build_v20.sh` (same steps as `build.sh`, writes only into `build_v20/`, deletes nothing,
refuses to run when `build_v20/probe.apk` exists). `build.sh` and `build/` are untouched.
Originals of the changed files: `~/backups/work-2026-11-18/probe-v20-2026-11-19/`.

## What changed (LiveService.java +47/-3, manifest version only, .gitignore +1 line)
Only the live stream. No other mode, no attestation or signing code, no permission, no
network security config change.

- `loadLabCa()`: runs at service start and on every re-point. If the CSE URL is https it reads
  `lab_ca.crt` from the app's external files dir, requires exactly one certificate in it, and builds
  an `SSLSocketFactory` whose only trust anchor is that certificate (no system CAs). On any error the
  factory stays null and one line is logged.
- `open(url)`: the one place the service opens a connection. Both `http()` and `httpBody()` use it,
  so every request goes through it: AE create/GET/PUT, the 7 containers, pch, cmd subscription, the
  five cin posts, the ack post, the radioTs post, the pch/pcu long poll and its response post.
  For an https URL it sets the lab factory or throws; it never uses the platform default trust.
  Host name verification is not touched (platform default: the certificate must match the URL host;
  a URL with an IP address needs that IP as a subjectAltName).
- `emit()`: with an https CSE and no factory, the oneM2M block is skipped (nothing is posted, no
  registration attempt). `latest.json` is still written locally as before.
- Re-point: the factory is cleared before the target changes and rebuilt after.

## Cases, by reading the code (none run on a phone)
| Case | Result |
|---|---|
| `http://127.0.0.1:...` | `loadLabCa` returns at once and logs nothing; `open` returns the same connection object v19 made; the gate in `emit` is false. Same requests, same log lines as v19. |
| https, good `lab_ca.crt`, server cert from that CA, host matches | one log line `https cse: trusting only lab_ca.crt`; stream as usual over TLS. |
| https, file missing / unreadable / not a certificate / more than one certificate | one log line `https cse but lab_ca.crt not usable (...): nothing will be posted`; `emit` skips the CSE; a poller left from an earlier CSE gets an exception from `open` and sleeps 1 s per loop. Nothing is sent. No retry of the file until the next start or re-point. |
| https, server cert from another CA (public CAs included) | handshake fails; `http()` returns -1; `ensureAe` logs `ok=false ae=-1` each period; nothing is posted. |
| https, right CA, wrong host name | refused by the platform host name check; same as the row above. |
| re-point http loopback -> https | factory built for the new target; `aeReady=false`, so registration runs against the https CSE. If the file is missing: posting stops. |
| re-point https -> http loopback | factory cleared, not rebuilt; behaviour as v19. |
| `HTTPS://` in capitals | treated as https (scheme compared without case; `open` also checks the connection type). |

Other notes: an https redirect is followed with the same factory (still lab CA only); http->https
redirects are not followed by the platform. The `mec016 --ez switch true` path starts this service
with the URI the MEC service returns; if that URI is https it now needs `lab_ca.crt` too (in v19 it
would have used the system CAs). A re-point happens only when `cse` or `rn` differs, so after
replacing `lab_ca.crt` use `live-stop` and start again.

## Placing the lab CA and starting the stream
```
S=<serial>; D=/sdcard/Android/data/org.edgefollow.probe/files
adb -s $S push <lab-ca-certificate.pem> $D/lab_ca.crt        # the CA CERTIFICATE only, never its key
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode live -e cse https://<the front door's IP address>:<its port>/cse-mn-a -e origin Cphone-DEVC --ei period 5
adb -s $S shell tail -n 5 $D/live_status.txt                 # expect "https cse: trusting only lab_ca.crt", then "ensureAe ok=true ..."
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode live-stop
```
The file is PEM or DER, one certificate. The directory exists after the app has run once.
The phone must reach the front door's IP address itself (no `adb reverse` needed). Use the IP address and the
port the front door listens on, never a host name and never a forward that changes the port: `phone/tls_front.py`
accepts only a Host header equal to its own listen address, and the lab certificate names that IP address only.

## What this does NOT give
- It authenticates the server to the phone. The phone is not authenticated to the server: no client
  certificate; the CSE still sees only the `X-M2M-Origin` header.
- The lab CA's private key lives on the lab PC. Whoever holds it can impersonate the CSE to the phone.
- `lab_ca.crt` sits in app external storage. adb shell can replace it; so can anything with access
  to that directory. It is a lab trust anchor, not a protected one.
- The app is debug-signed (standard Android debug keystore). Anyone with that keystore can build an
  update the phone accepts.
- No pinning of the server key, no revocation check.

## Install checklist (for the person with the phone)
1. `adb install -r` ONLY. NEVER uninstall, never `pm clear`: both delete the app's data and the
   hardware-backed keys the phones kept. If `install -r` fails, stop and report; do not uninstall
   to "fix" it.
2. Before installing, check the signer of what is on the phone:
   `adb -s $S shell pm path org.edgefollow.probe`, `adb -s $S pull <that path> installed.apk`,
   `apksigner verify --print-certs installed.apk` -> must show `49f43629…7fbf`. Also
   `sha256sum build_v20/probe.apk` -> `bb2d66e9…2dc7`. If either differs, stop.
3. Start with the phone whose keys matter less.
4. `adb -s $S install -r phone/probe_app/build_v20/probe.apk`, then
   `adb -s $S shell dumpsys package org.edgefollow.probe | grep -E 'versionCode|versionName'` -> 20 / 20.
5. Confirm an old key alias still signs:
   `adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode sign -e alias <kept-alias> -e challenge 0102`,
   `adb -s $S shell cat $D/sign.json` -> same result as before the update (`ok=true` for an unbound key).
6. Regression: one `live` run against the usual `http://127.0.0.1:...` CSE; `live_status.txt` must
   look like v19 (no line about `lab_ca.crt`).
7. Then the https cases above, including the negative ones (no file; a server certificate from
   another CA) and check that the CSE received nothing in those.

## Not checked (needs a phone and a TLS CSE)
Everything at run time: the TLS handshake, that the system CAs are really excluded, host name
refusal, redirect behaviour, the re-point sequences, and that the update keeps the keys.
