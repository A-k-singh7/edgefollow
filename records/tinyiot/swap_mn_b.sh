#!/usr/bin/env bash
# Replace ACME's MN-B (:8202) with tinyIoT under the same identity (id-mn-b / cse-mn-b).
set -uo pipefail
VENV=/home/edgefollow/estimed-venv; RUN=/home/edgefollow/estimed-run
R=/var/tmp/cse-survey/run-mn-b; BIN=/var/tmp/cse-survey/tinyIoT/source/server/server
H=(-H "X-M2M-Origin: CAdmin" -H "X-M2M-RI: swap" -H "X-M2M-RVI: 4" -H "Accept: application/json")
for p in /proc/[0-9]*; do   # ACME mn-b only; never pkill -f
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
    case "$c" in *zsh*|*bash*) continue;; *"$VENV/bin/acmecse"*"$RUN/mn-b"*) kill -TERM "${p#/proc/}";; esac
done
for _ in $(seq 1 15); do ss -ltn | grep -q '127.0.0.1:8202 ' || break; sleep 1; done
ss -ltn | grep -q '127.0.0.1:8202 ' && { echo "8202 still held"; exit 1; }
curl -s -o /dev/null -w "  stale id-mn-b at IN: DELETE %{http_code}\n" -X DELETE "${H[@]}" http://127.0.0.1:8200/cse-in/id-mn-b
rm -rf "$R"; mkdir -p "$R"; cp -r "$(dirname "$BIN")/sdt_definitions" "$R/"
( cd "$R" && setsid "$BIN" > "$R/stdout.log" 2>&1 < /dev/null & )
for _ in $(seq 1 20); do
    curl -s "${H[@]}" "http://127.0.0.1:8200/cse-in?fu=1&ty=16" | grep -q id-mn-b && \
        ss -ltn | grep -q '127.0.0.1:8202 ' && { echo "  tinyIoT MN-B up and registered"; exit 0; }
    sleep 1
done
echo "  tinyIoT did not register"; tail -5 "$R/stdout.log"; exit 1
