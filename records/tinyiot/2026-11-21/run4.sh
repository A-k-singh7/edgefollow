#!/bin/bash
# Run 4 (2026-11-21): part A of run 3, complete.  Run 3 (2026-11-21): tinyIoT's CSEBaseAnnc naming. Part A as is (fresh IN record) -> does the IN get a route?
# Part B with a stated workaround: the CSEBaseAnnc pre-created under the name tinyIoT assumes (id-mn-b_cba), then
# ACME->tinyIoT, tinyIoT->ACME, scenario, with the IN's routes printed after every move. Restore + control + reset.
# Run INSIDE `flock -o /home/edgefollow/estimed-run/.live.lock`.
set -u
OUT=/home/edgefollow/estimed-run/tinyiot-2026-11-21/run4; mkdir -p $OUT
PY=/home/edgefollow/edgefollow-lab/.venv/bin/python
HERE=<scratch>/tinyiot
SNAP=<scratch>/build-mec011/scripts/snap.py
BIN=/var/tmp/cse-survey/tinyIoT/source/server/server
ACME_CMD=(/home/edgefollow/estimed-venv/bin/python3 /home/edgefollow/estimed-venv/bin/acmecse --headless --config acme.ini
          --base-directory /home/edgefollow/estimed-run/mn-b --log-level info)
IN=http://127.0.0.1:8200
H=(-H "X-M2M-Origin: CAdmin" -H "X-M2M-RI: run3" -H "X-M2M-RVI: 4" -H "Accept: application/json")
export PYTHONDONTWRITEBYTECODE=1
cd /home/edgefollow/edgefollow
RESET='import sys; sys.path.insert(0, "estimed"); import handover; handover.reset()'
routes() { curl -s "${H[@]}" "$IN/cse-in?fu=1&lbl=aei:Cvehicle01"; }
cbas() { curl -s "${H[@]}" "$IN/cse-in?fu=1&ty=10005"; }
lnk_of() { curl -s "${H[@]}" "$IN/$1" | grep -o '"lnk": *"[^"]*"' | sed 's/.*: *"//; s/"$//'; }
del_tinyiot_cbas() {   # only CSEBaseAnnc records whose lnk is tinyIoT's (/id-mn-b/cse-mn-b); never ACME's own
  for u in $(cbas | grep -o 'cse-in/[^"]*'); do
    [ "$(lnk_of $u)" = "/id-mn-b/cse-mn-b" ] && curl -s -o /dev/null -w "  DELETE $u (lnk /id-mn-b/cse-mn-b): %{http_code}\n" -X DELETE "${H[@]}" "$IN/$u"
  done; }
step() { name=$1; shift; echo "=== $name $(date +%T)"; timeout -s INT -k 20 300 "$@" > $OUT/$name.out 2>&1; rc=$?
         echo "--- $name exit $rc: $(grep -E 'RESULT|"ok": (true|false)' $OUT/$name.out | tail -1 | cut -c1-160)"; echo "    routes now: $(routes)"; }
restore() {
  echo "=== restore $(date +%T)"
  for p in /proc/[0-9]*; do c=$(tr '\0' ' ' < $p/cmdline 2>/dev/null) || continue
    case "$c" in "$BIN "*) kill -TERM ${p#/proc/} && echo "  stopped tinyIoT ${p#/proc/}";; esac; done 2>/dev/null
  for _ in $(seq 1 15); do ss -ltn | grep -q '127.0.0.1:8202 ' || break; sleep 1; done
  curl -s -o /dev/null -w "  stale id-mn-b at IN: DELETE %{http_code}\n" -X DELETE "${H[@]}" $IN/cse-in/id-mn-b
  del_tinyiot_cbas
  if ! ss -ltn | grep -q '127.0.0.1:8202 '; then
    ( cd /home/edgefollow/estimed-run/mn-b && setsid "${ACME_CMD[@]}" > $OUT/acme-mn-b-restart.log 2>&1 < /dev/null & )
  fi
  for _ in $(seq 1 40); do
    curl -s "${H[@]}" "$IN/cse-in?fu=1&ty=16" | grep -q id-mn-b && ss -ltn | grep -q '127.0.0.1:8202 ' \
      && { echo "  ACME MN-B back and registered ($(date +%T))"; return 0; }
    sleep 1
  done
  echo "  ACME MN-B NOT back"; return 1; }

python3 -I -B $SNAP take $OUT/lab.before.json > /dev/null
echo "=== prepare $(date +%T)"; $PY -B -c "$RESET"; echo "  routes: $(routes)"; echo "  CSEBaseAnnc before: $(cbas)"
del_tinyiot_cbas
case "$(routes)" in *aeA_*) echo "STOP: a route is still announced; no swap"; exit 1;; esac
echo "=== swap $(date +%T)"; bash /var/tmp/cse-survey/swap_mn_b.sh > $OUT/swap.out 2>&1; rc=$?; tail -2 $OUT/swap.out
if [ $rc -eq 0 ]; then
  echo "--- PART A, complete: no workaround, one tinyIoT process throughout"
  step a1_handover_acme_to_tinyiot $PY -B estimed/handover.py
  step a2_handover_tinyiot_to_acme $PY -B $HERE/reverse.py
  step a3_scenario_mn_b_tinyiot $PY -B estimed/scenario.py --json
  echo "    CSEBaseAnnc: $(cbas)"
  cp /var/tmp/cse-survey/run-mn-b/stdout.log $OUT/tinyiot-stdout.log 2>/dev/null
else
  echo "swap FAILED: no tinyIoT runs"
fi
echo "=== reset before the restore"; $PY -B -c "$RESET"; echo "  routes: $(routes)"
restore
echo "  routes after restore: $(routes)"; echo "  CSEBaseAnnc after restore: $(cbas)"
step c1_handover_all_acme_after $PY -B estimed/handover.py
echo "=== final reset"; $PY -B -c "$RESET"; echo "  routes at the end: $(routes)"
python3 -I -B $SNAP take $OUT/lab.after.json > /dev/null
echo "lab: $(python3 -I -B $SNAP diff $OUT/lab.before.json $OUT/lab.after.json | tr '\n' ' ' | cut -c1-300)"
echo "=== DONE $(date +%T)"
