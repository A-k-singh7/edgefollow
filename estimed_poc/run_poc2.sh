#!/usr/bin/env bash
# ESTIMED PoC 2 on two phones: the Pixel 10a as the vehicle (AE phone) and the Nothing A142 as the roadside unit
# (AE rsu), phone/estimed_poc2.py with the phone save and restore of phone/lib_guard.sh.
# Location services are switched on for the run. On exit, whatever happens, location, airplane mode, Wi-Fi and mobile
# data go back to their state at start on BOTH phones, every adb reverse forward is removed, and the probe permissions
# this run granted on the roadside phone are revoked (phone/lib_guard.sh); a TERM to this driver stops the PoC through
# its own finally first. Stop it with `kill -TERM <pid>`. Arguments go to phone/estimed_poc2.py.
set -uo pipefail
# Every path below can be overridden from the environment (the lab's driver tests run these drivers against fakes);
# the defaults are the lab values.
R=${R:-/home/edgefollow/edgefollow}
PY=${PY:-/home/edgefollow/edgefollow-lab/.venv/bin/python}
export ANDROID_SERIAL=${ANDROID_SERIAL:-${PHONE_A_SERIAL:?set PHONE_A_SERIAL to the adb serial of phone-A}}
ADB_BIN=${ADB_BIN:-$HOME/android-tools/platform-tools/adb}
ADB="$ADB_BIN -s $ANDROID_SERIAL"
RUN=${RUN:-/home/edgefollow/estimed-run}
source "$R/phone/lib_guard.sh" || { echo "phone/lib_guard.sh missing"; exit 9; }
# MAIN and NAME: another program under the same phone set-up and the same restore, e.g.
#   MAIN=$R/estimed_poc/fl_capture.py NAME=fl_capture bash estimed_poc/run_poc2.sh capture ...
# The defaults are the PoC, as before.
MAIN=${MAIN:-$R/phone/estimed_poc2.py}
NAME=${NAME:-estimed_poc2}
OUT=$RUN/${NAME}_run.txt
: > "$OUT"
up() { ss -ltn | grep -q ":$1\b"; }
for p in 8200 8201 8202; do up $p || { echo "oneM2M topology is not up (port $p)"; exit 2; }; done
# The probe's location service cannot start behind the lock screen (Android 12+ foreground-service rules):
# wait up to 10 minutes for someone to unlock the phone.
for i in $(seq 1 120); do
  $ADB shell dumpsys window | grep -q "isKeyguardShowing=false" && break
  [ "$i" = 1 ] && echo "waiting for the phone to be unlocked..." | tee -a "$OUT"
  sleep 5
done
$ADB shell dumpsys window | grep -q "isKeyguardShowing=false" || { echo "phone still locked after 10 min: not started" | tee -a "$OUT"; exit 3; }
echo "phone unlocked: starting" | tee -a "$OUT"
LOC0=$($ADB shell cmd location is-location-enabled | tr -d '\r')
export RSU_SERIAL=${RSU_SERIAL:-${PHONE_B_SERIAL:?set PHONE_B_SERIAL to the adb serial of phone-B}}
NP="$ADB_BIN -s $RSU_SERIAL"
# The run text names the phones by label, never by serial number (2026-11-19): phone-A is the phone ANDROID_SERIAL
# names, phone-B the one RSU_SERIAL names (g_label in phone/lib_guard.sh). A sitting copies this text into its records.
# The roadside phone runs the probe's location service too, so it must be unlocked as well (same 10 minutes).
for i in $(seq 1 120); do
  $NP shell dumpsys window | grep -q "isKeyguardShowing=false" && break
  [ "$i" = 1 ] && echo "waiting for the roadside phone (phone-B) to be unlocked..." | tee -a "$OUT"
  sleep 5
done
$NP shell dumpsys window | grep -q "isKeyguardShowing=false" || { echo "roadside phone still locked after 10 min: not started" | tee -a "$OUT"; exit 3; }
g_save "$ANDROID_SERIAL"; echo "$G_SAID" | tee -a "$OUT"
g_save "$RSU_SERIAL"; echo "$G_SAID" | tee -a "$OUT"
GRANTED=""   # the probe permissions THIS run grants on the roadside phone; revoked on exit
restore() {
  local p
  g_restore "$RSU_SERIAL" | tee -a "$OUT"
  for p in $GRANTED; do $NP shell pm revoke org.edgefollow.probe android.permission.$p >/dev/null 2>&1; done
  [ -n "$GRANTED" ] && echo "revoked on phone-B:$GRANTED" | tee -a "$OUT"
  g_restore "$ANDROID_SERIAL" | tee -a "$OUT"
  echo "location restored to: $($ADB shell cmd location is-location-enabled | tr -d '\r') (was $LOC0)" | tee -a "$OUT"
}
trap restore EXIT
up 8300 || (cd "$R" && setsid "$PY" demo/mec040.py > $RUN/demo_mec040.log 2>&1 < /dev/null &)
$ADB reverse tcp:8201 tcp:8201 >/dev/null
$ADB reverse tcp:8202 tcp:8202 >/dev/null
$ADB shell cmd location set-location-enabled true
sleep 5
reset_phone() {
  $ADB wait-for-device
  g_radio "$ANDROID_SERIAL"
  $ADB reverse tcp:8201 tcp:8201 >/dev/null
  $ADB reverse tcp:8202 tcp:8202 >/dev/null
  $ADB shell am start -n org.edgefollow.probe/.Main -e mode live-stop >/dev/null
  sleep 3
  PHONE_ESTIMED="$R/estimed" "$PY" - <<'PY'
import os, sys; sys.path.insert(0, os.environ["PHONE_ESTIMED"])
import handover as ho
for e in (ho.EDGE_A, ho.EDGE_B):
    ho.delete_ae(e, ae="phone", origin="Cphone-DEVC")
PY
  $ADB shell am start -n org.edgefollow.probe/.Main -e mode live -e cse http://127.0.0.1:8201/cse-mn-a \
     -e origin Cphone-DEVC --ei period 5 >/dev/null
  sleep 16
  "$PY" "$R/phone/onem2m_acp.py" >/dev/null
}
reset_phone
# the roadside sensor: Nothing phone, AE `rsu`, originator Crsu-NP2A, streaming to edge A
PRE=$($NP shell dumpsys package org.edgefollow.probe | tr -d '\r' | grep -oE 'android\.permission\.[A-Z_]+: granted=true' \
      | sed -E 's/^android\.permission\.//; s/: granted=true$//')
for p in ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION ACCESS_BACKGROUND_LOCATION READ_PHONE_STATE ACTIVITY_RECOGNITION; do
  echo "$PRE" | grep -qx "$p" && continue
  $NP shell pm grant org.edgefollow.probe android.permission.$p >/dev/null 2>&1 && GRANTED="$GRANTED $p"
done
$NP reverse tcp:8201 tcp:8201 >/dev/null
$NP shell cmd location set-location-enabled true
$NP shell am start -n org.edgefollow.probe/.Main -e mode live-stop >/dev/null
sleep 3
PHONE_ESTIMED="$R/estimed" "$PY" - <<'PY'
import os, sys; sys.path.insert(0, os.environ["PHONE_ESTIMED"])
import handover as ho
ho.delete_ae(ho.EDGE_A, ae="rsu", origin="Crsu-NP2A")
PY
$NP shell am start -n org.edgefollow.probe/.Main -e mode live -e cse http://127.0.0.1:8201/cse-mn-a \
   -e origin Crsu-NP2A -e rn rsu --ei period 5 >/dev/null
sleep 16
g_run 1200 "$RUN/$NAME.log" "$PY" "$MAIN" "$@"
rc=$?
echo "$NAME|rc=$rc|$(grep -E 'RESULT' $RUN/$NAME.log | tail -1 | sed 's/^ *//')" | tee -a "$OUT"
