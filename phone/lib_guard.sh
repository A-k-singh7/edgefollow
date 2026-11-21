# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
# Sourced by the phone drivers (estimed_poc/run_poc2.sh here), after they set ADB_BIN. Held by the lab's driver
# tests, which run every driver against a fake adb and a fake suite.
#
# g_run SECONDS LOG CMD...  runs one suite or PoC under `timeout -s INT -k 30` in the background and waits for it.
#   A TERM, INT or HUP to the driver -- or to its whole process group -- is forwarded to timeout as SIGINT, which
#   timeout passes to the Python child: its own finally runs (test_phone_wlan and test_phone_transitions put Wi-Fi
#   and airplane mode back there), and the driver exits, and restores, only after the child is gone.
#   Until 2026-10-29 the drivers ran `timeout 1200`, which ends the child with SIGTERM and so skips finally; and
#   timeout moves itself into its own process group, so killing the driver's group left the suite running on the
#   phone while the driver restored around it. Stop a driver with `kill -TERM <pid>`: a bash started in the
#   background ignores INT.
# g_save SERIAL  records the phone's airplane mode, Wi-Fi, mobile data and location (call it before changing any).
# g_radio SERIAL  puts airplane mode, Wi-Fi and mobile data back to those values.
# g_restore SERIAL  stops the probe's stream, puts the radio and location back and removes every adb reverse
#   forward on the phone (a forward gives every app on it a route to the unauthenticated CAdmin origin).
# g_label SERIAL  the name a phone has in every line this file prints: phone-A for the phone ANDROID_SERIAL names,
#   phone-B for the one RSU_SERIAL names, phone-other for any other. Since 2026-11-19 no line carries a serial number:
#   the drivers tee the "at start" and "restored" lines into their run text, and a sitting copies that text into its
#   records. The serial still goes to adb, so nothing done to a phone has changed.
# A SIGKILL of the driver still skips all of this: check the phone afterwards.

G_TPID=
g_stop() {
  if [ -n "$G_TPID" ] && kill -0 "$G_TPID" 2>/dev/null; then
    echo "driver signalled: SIGINT to timeout pid $G_TPID, waiting for the child's own cleanup" >&2
    kill -INT "$G_TPID" 2>/dev/null
    local i; for i in $(seq 1 75); do kill -0 "$G_TPID" 2>/dev/null || break; sleep 1; done
  fi
}
trap 'g_stop; exit 130' INT TERM HUP

g_run() {
  local t=$1 log=$2 rc; shift 2
  timeout -s INT -k 30 "$t" "$@" > "$log" 2>&1 &
  G_TPID=$!
  wait "$G_TPID"; rc=$?
  G_TPID=
  return $rc
}

g_get() { "$ADB_BIN" -s "$1" shell settings get global "$2" | tr -d '\r'; }
g_loc() { "$ADB_BIN" -s "$1" shell cmd location is-location-enabled | tr -d '\r'; }
g_label() {
  if [ -n "${ANDROID_SERIAL:-}" ] && [ "$1" = "$ANDROID_SERIAL" ]; then echo phone-A
  elif [ -n "${RSU_SERIAL:-}" ] && [ "$1" = "$RSU_SERIAL" ]; then echo phone-B
  else echo phone-other; fi
}

g_save() {   # sets G_AIR_<k> G_WIFI_<k> G_DATA_<k> G_LOC_<k> (k = the serial, non-alphanumerics as _) and G_SAID
  local s=$1 k=${1//[^A-Za-z0-9]/_}
  printf -v "G_AIR_$k" '%s' "$(g_get "$s" airplane_mode_on)"
  printf -v "G_WIFI_$k" '%s' "$(g_get "$s" wifi_on)"
  printf -v "G_DATA_$k" '%s' "$(g_get "$s" mobile_data)"
  printf -v "G_LOC_$k" '%s' "$(g_loc "$s")"
  local a=G_AIR_$k w=G_WIFI_$k d=G_DATA_$k l=G_LOC_$k
  G_SAID="$(g_label "$s") at start: airplane=${!a} wifi=${!w} data=${!d} location=${!l}"
}

g_radio() {
  local s=$1 k=${1//[^A-Za-z0-9]/_}; local a=G_AIR_$k w=G_WIFI_$k d=G_DATA_$k
  case "${!a:-}" in 0) "$ADB_BIN" -s "$s" shell cmd connectivity airplane-mode disable ;;
                    1) "$ADB_BIN" -s "$s" shell cmd connectivity airplane-mode enable ;; esac >/dev/null 2>&1
  case "${!w:-}" in 1) "$ADB_BIN" -s "$s" shell svc wifi enable ;; 0) "$ADB_BIN" -s "$s" shell svc wifi disable ;; esac >/dev/null 2>&1
  case "${!d:-}" in 1) "$ADB_BIN" -s "$s" shell svc data enable ;; 0) "$ADB_BIN" -s "$s" shell svc data disable ;; esac >/dev/null 2>&1
}

g_restore() {
  local s=$1 k=${1//[^A-Za-z0-9]/_}; local a=G_AIR_$k w=G_WIFI_$k d=G_DATA_$k l=G_LOC_$k
  "$ADB_BIN" -s "$s" shell am start -n org.edgefollow.probe/.Main -e mode live-stop >/dev/null 2>&1
  g_radio "$s"
  case "${!l:-}" in true|false) "$ADB_BIN" -s "$s" shell cmd location set-location-enabled "${!l}" >/dev/null 2>&1 ;; esac
  "$ADB_BIN" -s "$s" reverse --remove-all >/dev/null 2>&1
  sleep 3
  echo "$(g_label "$s") restored: airplane=$(g_get "$s" airplane_mode_on) wifi=$(g_get "$s" wifi_on) data=$(g_get "$s" mobile_data)" \
       "location=$(g_loc "$s") (was ${!a:-?} ${!w:-?} ${!d:-?} ${!l:-?}); reverse [$("$ADB_BIN" -s "$s" reverse --list | tr -d '\r')]"
}
