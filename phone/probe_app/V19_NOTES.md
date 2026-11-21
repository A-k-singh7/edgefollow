# probe app v19 (UNCOMMITTED, built 2026-10-15, not installed/tested on a device)

*Historical (2026-11-21): written when v19 was built. v19 was installed later and ran the sitting of 2026-11-19;
the source in this folder is v20 (see README.md).*

APK: `phone/probe_app/build/probe.apk` (gitignored), sha256
`2670ac4ba182d39797f6fbd907d300c2d7e1f36603f87d399e6b8c7293ffaf8a`, 49,660 B.
`aapt2 dump badging`: `versionCode='19' versionName='19'`, minSdk 30, targetSdk 30 (unchanged).
Previous build (v18, sha256 `5e505f48…5d84`) and its exact sources/manifest/build.sh are kept in
`phone/probe_app/build_v18_prev/` so `diff -r build_v18_prev/src src` shows the whole v19 change.

Signing: same key as v18: `~/.android/debug.keystore`, alias `androiddebugkey` (CN=Android Debug),
cert SHA-256 `49f43629df6dc199291d9b26420bbeb1aea785fda950511621342d9564f77fbf` (both APKs checked with
`apksigner verify --print-certs`), v3 scheme. `adb install -r` is an upgrade and keeps app data.

## What changed in v19 (additions only; manifest differs from v18 only in the version)
1. `capture` mode (Main.java). Extras: `dur` 1..600 s (default 60; `--ei` or `-e` both accepted),
   `rate` fastest|game|ui (default fastest), `types` csv of sensor type ints, `out` file name
   (`[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}`, default `capture_<wall_ms>.jsonl`). Bad value -> status.txt
   `ERROR ... IllegalArgumentException`, `done_capture`, no capture.
   - Default types: 1,2,4,5,8,9,10,11,14,15,16,35 + every vendor type >= 65536 present as a non-wakeup,
     non-one-shot, non-trigger sensor. One sensor per type: the default sensor if it is non-wakeup,
     else the first non-wakeup one of that type; types with none are listed in the header `skipped`
     with reason `absent` or `only wakeup/one-shot/trigger sensors` (expect 8 proximity there on phones
     whose proximity is wake-up only).
   - `registerListener(l, s, SENSOR_DELAY_<rate>, maxReportLatencyUs=0, handler)` on its own
     HandlerThread. The callback copies the event (`values.clone()`, the framework reuses SensorEvent)
     into an `ArrayBlockingQueue` of 65,536 with `offer` (never blocks; full -> drop counted, total and
     per type). One writer thread formats JSON lines into a 1 MiB BufferedWriter, flushed on each
     confound line.
   - File in `getExternalFilesDir(null)`:
     line 1 `{"schema":"probe.capture/1","model","sdk","app_version":19,"started_elapsed_ns","started_wall_ms",
     "rate","rate_delay_constant","max_report_latency_us":0,"dur_s","types_requested","queue_capacity",
     "sensors":[{"type","name","vendor","version","resolution","maxRange","minDelay_us","power_mA","reportingMode","fifoMax"}],
     "skipped":[...],"register_failed":[...]}`;
     events `{"t":type,"ts":event.timestamp,"v":[...],"a":accuracy}` (non-finite floats -> null);
     1 Hz `{"c":{"batt_temp_c","batt_level","plugged","screen_on","thermal_status","dropped_so_far","elapsed_ns","wall_ms"}}`
     (thermal = PowerManager.getCurrentThermalStatus, 0 NONE..6 SHUTDOWN; plugged 0 none 1 AC 2 USB 4 wireless);
     `{"acc":{"t","a","ts":elapsedRealtimeNanos}}` on accuracy change;
     last line `{"end":{"elapsed_ns","wall_ms","counts":{"<type>":n},"total","dropped","dropped_by_type":{},"confound_dropped","write_error"}}`.
     Then `done_capture`. One capture at a time (a second -> ERROR "capture already running").
   - Screen: the activity already sets FLAG_KEEP_SCREEN_ON in onCreate for every mode and finishes only
     when the mode returns, so the flag is held for exactly the capture. Not a wakelock: no new
     permission, auto-released if the activity dies, and since Android 9 an app not in the foreground
     gets no continuous-sensor events at all, so a PARTIAL wakelock would keep the CPU up and still lose
     the data. The flag does NOT turn the screen on and does not survive the power button: wake +
     unlock first; `screen_on` in each confound line shows if it went off.
   - Only change on a shared path: while a capture runs, another command arriving (e.g. `clock`) does
     not `finish()` the activity (it would drop the flag and background the app). With no capture
     running, every existing mode behaves exactly as v18.
2. `clock` mode: `--ei n N` (default 50, 1..10000) back-to-back reads of
   `SystemClock.elapsedRealtimeNanos()`, `System.currentTimeMillis()`, `SystemClock.uptimeMillis()` ->
   `clock.json` `{"schema":"probe.clock/1","model","sdk","n","samples":[{"elapsed_ns","wall_ms","uptime_ms"}]}`.
3. `ClockCli` class (not a component, manifest untouched): run by `app_process` from adb; prints
   `<elapsedRealtimeNanos> <currentTimeMillis>` per newline on stdin. This is what
   `phone/clock_offset.py --method cli` uses (one JVM start, then ~1 USB round trip per reading).
4. versionCode/versionName 19/"19" (manifest + build.sh).

HIGH_SAMPLING_RATE_SENSORS: with targetSdk 30 the Android 12 200 Hz cap does not apply anyway; the
permission stays declared as before.

## Host tool: phone/clock_offset.py (+ phone/test_clock_offset.py, 33 passed, 0 failed)
Clock facts it relies on (from Android/kernel source as known, NOT re-verified on these phones):
elapsedRealtimeNanos = clock_gettime(CLOCK_BOOTTIME); SensorEvent.timestamp is in the same base;
/proc/uptime field 1 = ktime_get_boottime (CLOCK_BOOTTIME) printed with 2 decimals (10 ms, truncated);
/proc/timer_list "now" is CLOCK_MONOTONIC (excludes deep sleep) and root-only -> not used.
Estimator: min-RTT sample, offset = phone - (t0+t1)/2 (+quant/2), bound = RTT/2 + quant/2 (valid for any
link asymmetry); drift (Theil-Sen, diagnostic) and a consistency flag (a phone-clock jump -> False).
Conversion: bracket the capture with one estimate before and one after -> linear interpolation,
bound = max(before, after) bounds; a single estimate grows the bound by `--drift-allow-ppm`
(default 500 = Linux max NTP slew of CLOCK_MONOTONIC).

## Test commands (orchestrator; pick the phone with -s)
```
S=<serial>; D=/sdcard/Android/data/org.edgefollow.probe/files
adb -s $S install -r phone/probe_app/build/probe.apk
adb -s $S shell dumpsys package org.edgefollow.probe | grep -E 'versionCode|versionName'   # versionCode=19 ... versionName=19
# regression (unchanged from v18): info + default attest
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode info            # sensors.json, cameras.json, done_info
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode attest -e challenge 00112233445566778899aabbccddeeff
#   expect attest.json with pop_sig and no "params" key, as v16/v18

# A) ClockCli by hand: 3 newlines -> 3 lines "<ns> <ms>", ns increasing, ms ~ phone wall clock
printf '\n\n\n' | adb -s $S shell 'CLASSPATH=$(pm path org.edgefollow.probe | head -n1 | cut -d: -f2) exec app_process /system/bin org.edgefollow.probe.ClockCli'
#   if this prints a Java error instead, use --method uptime below and report the error
# B) offset before the capture (cli), plus the uptime method as an independent cross-check
python3 phone/clock_offset.py measure --serial $S --method cli    --k 200 --out /path/est_before.json
python3 phone/clock_offset.py measure --serial $S --method uptime --k 200 --out /path/est_uptime.json
#   expect exit 0, consistent=True; cli bound: sub-ms to a few ms (not measured yet); uptime bound >= 5 ms.
#   CHECK: |offset_cli - offset_uptime| (mono) <= bound_cli + bound_uptime; if not, the CLOCK_BOOTTIME
#   claim or one method is wrong -> stop and report.
# C) capture (screen on + unlocked first; the flag keeps it on, it does not turn it on)
adb -s $S shell input keyevent KEYCODE_WAKEUP
adb -s $S shell rm -f $D/done_capture $D/cap1.jsonl
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode capture --ei dur 30 -e rate fastest -e out cap1.jsonl
adb -s $S shell "while [ ! -f $D/done_capture ]; do sleep 1; done; tail -n 2 $D/status.txt; head -c 3000 $D/cap1.jsonl | head -n 1; tail -n 1 $D/cap1.jsonl"
#   expect status "capture done file=cap1.jsonl events=N dropped=0"; header schema probe.capture/1 with
#   sensors[] and skipped[]; footer counts per type; about 30 {"c":..} lines; screen_on true throughout;
#   accel/gyro counts ~ dur * 1e6/minDelay_us (fastest). dropped > 0 is a finding, not a failure to hide.
adb -s $S pull $D/cap1.jsonl /path/cap1.jsonl
python3 phone/clock_offset.py measure --serial $S --method cli --k 200 --out /path/est_after.json
python3 phone/clock_offset.py convert --capture /path/cap1.jsonl --before /path/est_before.json \
    --after /path/est_after.json --out /path/cap1.host.jsonl
#   events gain host_ns (time.monotonic_ns base) + host_bound_ns; prints max bound
# D) variants
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode capture --ei dur 10 -e rate game -e types 1,4 -e out cap2.jsonl
#   header sensors = types 1 and 4 only, ~50 Hz each
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode capture --ei dur 601
#   negative: status.txt "ERROR ... dur must be 1..600 s", done_capture, no file
# E) clock mode
adb -s $S shell rm -f $D/clock.json $D/done_clock
adb -s $S shell am start -W -n org.edgefollow.probe/.Main -e mode clock --ei n 50
adb -s $S shell "while [ ! -f $D/done_clock ]; do sleep 0.2; done; cat $D/clock.json"
#   expect schema probe.clock/1, 50 samples, elapsed_ns non-decreasing, consecutive gaps ~ us
```
`done_<mode>` is touched when a mode finishes (also on error).

# v18 notes (unchanged in v19)

## What changed
1. `live`: optional extra `rn` (AE resource name, default `phone`, must match `[A-Za-z0-9_-]{1,64}`, else
   ignored). Used for the AE create, GET/PUT, containers, pch/pcu, cmd sub, radioTs, cin posts. A running
   service re-points when `cse` OR `rn` changes. Without `rn` everything (incl. log lines) is as v16.
   `api` stays `Nprobe.phone`. mec016 `switch` path unchanged (always `phone`).
2. `attest`: if any of `auth|timeout|invalidate|unlocked|alias` is present -> new path `attestBound`;
   otherwise the v16 code runs untouched.
   - `auth` none|strong|any -> setUserAuthenticationRequired(true) + setUserAuthenticationParameters(timeout,
     BIOMETRIC_STRONG | (any: +DEVICE_CREDENTIAL)). none = no binding.
   - `--ei timeout N` seconds (0 = per-use). `--ez invalidate B`, `--ez unlocked B` only set when given.
   - `alias X`: key generated under X (replacing an existing X) and KEPT; without alias it is deleted as before.
   - attest.json: `challenge, strongbox_requested, chain[], pop_sig|null (+pop_exception/pop_message/pop_cause),
     params{auth,timeout,invalidate,unlocked,alias,strongbox,key_kept[,replaced_existing]}, keyinfo{...}, ok`.
     keyinfo = what KeyInfo reports (userAuthRequired, userAuthType, userAuthTimeoutS, enforced by secure HW,
     invalidatedByBiometricEnrollment, insideSecureHardware, securityLevel). Keygen failure -> attest.json
     with ok=false + exception, and status ERROR.
3. `sign` (alias, challenge): initSign+sign, no prompt -> sign.json {ok, sig?, stage(load|initSign|sign|done),
   exception, message, cause, keyinfo}.
4. `sign_prompt` (alias, challenge, authn=strong|strong_or_credential): BiometricPrompt; CryptoObject-bound if
   initSign succeeds before auth (per-use keys), otherwise (time-bound key throws UserNotAuthenticated) a plain
   prompt then sign. 60 s timeout -> cancel. sign_prompt.json {ok, sig, authType (1 credential, 2 biometric),
   authTypeName, crypto_object, can_authenticate (BiometricManager code: 0 ok, 11 none enrolled, 12 no hw),
   failed_attempts, timeout, error_code/error | exception}. Always written.
5. Manifest: allowBackup=false; USE_BIOMETRIC (needed for 4); FOREGROUND_SERVICE_LOCATION declared (no-op at 30).
   **targetSdk kept at 30** - see below.
6. versionCode/versionName 18/"18" (manifest + build.sh).

### Why targetSdk stays 30
Raising to 35 cannot be verified here (no device) and changes behaviour of existing modes: at target 34+ a
`location` FGS throws SecurityException at startForeground unless location is granted at that moment
(v16 runs without it); START_STICKY restarts from background lose while-in-use location; target 33+
hides the FGS notification without POST_NOTIFICATIONS; 31+ precise/approximate location split; 35
edge-to-edge. That violates "existing modes byte-for-byte the same". Do it as its own change with a device test.

## Test commands (orchestrator; pick the phone with -s)
```
S=<serial>; D=/sdcard/Android/data/org.edgefollow.probe/files
adb -s $S install -r phone/probe_app/build/probe.apk
adb -s $S shell dumpsys package org.edgefollow.probe | grep -E 'versionCode|versionName'   # 18 / 18
# regression: v16 default attest (expect pop_sig present, no params key)
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode attest -e challenge 00112233445566778899aabbccddeeff
# 1) rn
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode live -e cse http://127.0.0.1:8201/cse-mn-a -e origin Cphone-DEVC -e rn phone2
#    expect AE /cse-mn-a/phone2 with imu/env/loc/radio/wlan/cmd/ack + pch; live_status.txt "rn=phone2"
# 2) auth-bound attest (needs secure lock screen; strong needs an enrolled fingerprint)
adb -s $S shell rm -f $D/attest.json $D/done_attest
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode attest -e challenge 00112233445566778899aabbccddeeff \
    -e auth strong --ei timeout 0 --ez invalidate true --ez unlocked true -e alias v18bio
adb -s $S shell cat $D/attest.json
#    expect ok=true, params as given, keyinfo.userAuthRequired=true userAuthType=2 timeout 0,
#    pop_sig=null with pop_exception (per-use: SignatureException/KeyStoreException "user not authenticated")
#    variant: -e auth any --ei timeout 30 -e alias v18any (if the phone was unlocked <30 s ago pop_sig MAY succeed)
# 3) sign without prompt
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode sign -e alias v18bio -e challenge 0102
adb -s $S shell cat $D/sign.json
#    per-use key: ok=false, stage=sign, exception java.security.SignatureException (cause KeyStoreException) or
#    UserNotAuthenticatedException; time-bound key (timeout>0) outside its window: stage=initSign,
#    exception android.security.keystore.UserNotAuthenticatedException. Unbound key: ok=true.
# 4) sign with prompt (phone unlocked, screen on, a human touches the sensor within 60 s)
adb -s $S shell am start -n org.edgefollow.probe/.Main -e mode sign_prompt -e alias v18bio -e challenge 0102 -e authn strong
adb -s $S shell "while [ ! -f $D/done_sign_prompt ]; do sleep 1; done; cat $D/sign_prompt.json"
#    finger: ok=true, sig, authType=2, crypto_object=true. No finger: ok=false, timeout=true,
#    error_code 5 (CANCELED) after ~60 s. strong_or_credential with PIN: authType=1.
#    Note: authn=strong_or_credential on a key made with auth=strong will fail at sign (key only accepts biometric).
```
`done_<mode>` is touched when a mode finishes (also on error). Verify sigs: ECDSA P-256/SHA-256 over the
challenge bytes with the leaf cert's public key from attest.json.
