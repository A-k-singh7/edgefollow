#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
#
# The MEC services the EdgeFollow scenario needs beside the CSEs: MEC 012 (RNIS, :8085), MEC 013 (location, :8101)
# and MEC 040 (federation, :8300). MEC 011 (:8091) and MEC 010-2 (:8092) are started by the tests that need them.
#
#   bash estimed/mec_services.sh start | stop | status
#
# Each service is started from this checkout's root as "$EDGEFOLLOW_PY <script>" (default: python3 on PATH). Its log
# and pid file go under $EDGEFOLLOW_RUN_DIR/mec/<checkout id> (default run dir: ~/estimed-run), where the checkout id
# is derived from the checkout's real path, so two checkouts never share pid files. A pid file holds the pid and the
# exact command it was started with. A port already in use is reported and left alone: no second copy is started.
# `stop` signals a pid only if that process still runs exactly the recorded command with its working directory at
# this checkout's root, then waits for it to exit. Our process that does not exit keeps its pid file, so a later stop
# can try again; a pid file that names a dead pid or someone else's process (a reused pid) is stale and is removed.
# EDGEFOLLOW_MEC_SERVICES ("name:port:script ...") replaces the service list (used by the tests).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
PY=${EDGEFOLLOW_PY:-$(command -v python3)}
ID=$(printf '%s' "$ROOT" | sha256sum | cut -c1-12)
RUN=${EDGEFOLLOW_RUN_DIR:-$HOME/estimed-run}/mec/$ID
SERVICES=${EDGEFOLLOW_MEC_SERVICES:-"mec012:8085:mec012/candidate.py mec013:8101:mec013_look/candidate.py mec040:8300:demo/mec040.py"}

held() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

alive() { kill -0 "$1" 2>/dev/null; }

recorded_pid() {   # the pid in a pid file, or nothing
    local f="$RUN/$1.pid" pid
    [ -f "$f" ] || return 1
    pid=$(head -n 1 "$f")
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    echo "$pid"
}

ours() {   # the recorded pid still runs exactly the recorded command, from this checkout
    local name=$1 pid want argv cwd
    pid=$(recorded_pid "$name") || return 1
    want=$(tail -n +2 "$RUN/$name.pid")
    argv=$({ tr '\0' '\n' <"/proc/$pid/cmdline"; } 2>/dev/null) || return 1
    cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null) || return 1
    [ -n "$want" ] && [ "$argv" = "$want" ] && [ "$cwd" = "$ROOT" ] || return 1
    echo "$pid"
}

start() {
    mkdir -p "$RUN"
    local rc=0 s name port script pid
    for s in $SERVICES; do
        IFS=: read -r name port script <<<"$s"
        if held "$port"; then
            echo "$name: :$port already in use; left alone"
            continue
        fi
        if ours "$name" >/dev/null; then
            echo "$name: already running from this checkout"
            continue
        fi
        rm -f "$RUN/$name.pid"                       # per checkout: a pid file not naming our process is stale
        (cd "$ROOT" && { setsid "$PY" "$script" </dev/null >"$RUN/$name.log" 2>&1 &
                         printf '%s\n%s\n%s\n' "$!" "$PY" "$script" >"$RUN/$name.pid"; })
        for _ in $(seq 1 40); do held "$port" && break; sleep 0.25; done
        if held "$port"; then echo "$name: started on :$port"; else echo "$name: did not come up (see $RUN/$name.log)"; rc=1; fi
    done
    return $rc
}

stop() {
    local rc=0 s name port script pid
    for s in $SERVICES; do
        IFS=: read -r name port script <<<"$s"
        if pid=$(ours "$name"); then
            kill "$pid" 2>/dev/null
            for _ in $(seq 1 40); do alive "$pid" || break; sleep 0.25; done
            if alive "$pid"; then
                echo "$name: pid $pid did not exit within 10 s; its pid file is kept"
                rc=1
                continue
            fi
            echo "$name: stopped (pid $pid)"
            rm -f "$RUN/$name.pid"
        elif pid=$(recorded_pid "$name") && alive "$pid"; then
            rm -f "$RUN/$name.pid"                   # a reused pid: the file is stale; the process is not ours
            echo "$name: pid $pid runs something else now; left alone, stale pid file removed"
        else
            [ -f "$RUN/$name.pid" ] && rm -f "$RUN/$name.pid"
            echo "$name: not running from this checkout"
        fi
    done
    return $rc
}

status() {
    local s name port script
    for s in $SERVICES; do
        IFS=: read -r name port script <<<"$s"
        if held "$port"; then echo "$name :$port up$(ours "$name" >/dev/null && echo ' (ours)')"; else echo "$name :$port down"; fi
    done
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
