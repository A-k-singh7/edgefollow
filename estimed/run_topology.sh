#!/usr/bin/env bash
# Start the ESTIMED oneM2M topology: one IN-CSE and two MN-CSEs.
#
#   IN-CSE    id-in     cse-in     :8200   (cloud - in-memory resource tree: a fresh IN on every start, see conf/in.ini)
#   MN-CSE-A  id-mn-a   cse-mn-a   :8201   -> registers to the IN
#   MN-CSE-B  id-mn-b   cse-mn-b   :8202   -> registers to the IN
#
# Configs live in this repo (conf/*.ini); runtime data, logs and PID files live
# OUTSIDE it under $RUN, so nothing untracked lands in the working tree.
#
# Two things this script exists to get right:
#
#  1. `--headless` is used so no text UI is rendered into the log, but the configs
#     set [logging] enableFileLogging=true. --headless ALONE suppresses every log
#     line including fatal ones, so a misconfigured CSE prints just the banner and
#     exits 0 -- effectively undiagnosable. File logging is what makes headless
#     operation debuggable.
#
#  2. The recorded PID is the CSE's OWN pid, resolved from /proc, NOT `$!`.
#     `$!` is the pid of `setsid`, whose child is the actual CSE (one higher).
#     Recording the wrong pid meant stop_topology.sh silently killed nothing, the
#     old generation kept the ports, and every "restart" died with
#     "Port already in use" while health checks answered from the stale process.
set -uo pipefail

VENV=${VENV:-/home/edgefollow/estimed-venv}
CONF=${CONF:-"$(cd "$(dirname "$0")" && pwd)/conf"}
RUN=${RUN:-/home/edgefollow/estimed-run}
LOGLEVEL=${LOGLEVEL:-info}

[ -x "$VENV/bin/acmecse" ] || { echo "acmecse not found at $VENV/bin/acmecse"; exit 2; }

# Resolve the running CSE pid for a node by matching its base directory in /proc.
# Never use `pkill -f <pattern>`: this tool runs commands via `bash -c "<cmd>"`,
# so the pattern is present in the invoking shell's own argv and pkill kills the
# shell. That cost three runs in this session before it was spotted.
cse_pid() {
    local name=$1 self=$$
    for p in /proc/[0-9]*; do
        local pid=${p#/proc/}
        [ "$pid" = "$self" ] && continue
        local c; c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
        [ -z "$c" ] && continue
        case "$c" in *zsh*|*bash*) continue;; esac
        case "$c" in
            *"$VENV/bin/acmecse"*"$RUN/$name"*) echo "$pid"; return 0;;
        esac
    done
    return 1
}

wait_up() {   # port resourceName
    local port=$1 rn=$2
    for _ in $(seq 1 40); do
        if curl -s -o /dev/null -H "X-M2M-Origin: CAdmin" -H "X-M2M-RI: rdy" \
                -H "X-M2M-RVI: 4" "http://127.0.0.1:$port/$rn" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

start_node() {   # name port resourceName
    local name=$1 port=$2 rn=$3
    if cse_pid "$name" >/dev/null; then
        printf "  %-6s already running (pid %s) - run stop_topology.sh first\n" \
               "$name" "$(cse_pid "$name")"
        return 1
    fi
    mkdir -p "$RUN/$name"
    cp -f "$CONF/$name.ini" "$RUN/$name/acme.ini"
    # exec: the forked subshell BECOMES setsid. Without it that bash stayed alive holding the caller's stdout, so a
    # caller reading this script's output through a pipe (x=$(...), subprocess capture) never saw EOF.
    ( cd "$RUN/$name" && exec setsid "$VENV/bin/acmecse" \
        --headless --config acme.ini --base-directory "$RUN/$name" \
        --log-level "$LOGLEVEL" </dev/null >"$RUN/$name/stdout.log" 2>&1 & )
    # The IN imports policies and scripts before it appears settled, so poll for
    # its pid rather than assuming a fixed delay.
    local pid=""
    for _ in $(seq 1 15); do
        sleep 1
        pid=$(cse_pid "$name") && break
    done
    [ -n "$pid" ] || { printf "  %-6s FAILED to start - see %s\n" \
        "$name" "$RUN/$name/logs/"; return 1; }
    echo "$pid" > "$RUN/$name/cse.pid"
    if wait_up "$port" "$rn"; then
        printf "  %-6s :%-5s pid %-8s up\n" "$name" "$port" "$pid"
    else
        printf "  %-6s :%-5s pid %-8s NOT ANSWERING - see %s\n" \
               "$name" "$port" "$pid" "$RUN/$name/logs/"
        return 1
    fi
}

ini_get() {   # node key -> the value in $CONF/<node>.ini (ports, names and CSE-IDs come from the config, not here)
    sed -n "s/^$2=//p" "$CONF/$1.ini" | head -n 1
}

# The IN must be up before the MNs attempt to register to it. Any node that fails makes the whole run fail: the
# exit status used to be 0 whatever happened (fixed 2026-10-29).
fail=0
for node in in mn-a mn-b; do
    start_node "$node" "$(ini_get "$node" httpPort)" "$(ini_get "$node" cseName)" || fail=1
done

# Port answering is NOT the same as registered. Each MN registers to the IN a few
# seconds AFTER its own HTTP port starts answering (csrMonitor in ACME), so a demo run
# fired immediately after bring-up can see only the edge that registered first -- that
# was the 9/10 "IN-CSE still holds both edges" failure. Wait until the IN actually holds
# BOTH remoteCSEs before declaring the topology ready.
# EXACTLY these remoteCSEs: a substring match took id-mn-ab for id-mn-a.
wait_registered() {   # IN port, IN resourceName, then the cseIDs that must be exactly the IN's remoteCSEs
    local port=$1 rn=$2 body; shift 2
    for _ in $(seq 1 30); do
        body=$(curl -s -H "X-M2M-Origin: CAdmin" -H "X-M2M-RI: regwait" -H "X-M2M-RVI: 4" \
               -H "Accept: application/json" "http://127.0.0.1:$port/$rn?fu=1&ty=16" 2>/dev/null)
        if python3 -I -c 'import json, sys
b = json.loads(sys.argv[1] or "{}")
sys.exit(sorted(b.get("m2m:uril", [])) != sorted(sys.argv[2] + "/" + c for c in sys.argv[3:]))' \
                "$body" "$rn" "$@" 2>/dev/null; then
            printf "  IN holds all edges: %s\n" "$body"
            return 0
        fi
        sleep 1
    done
    printf "  FAILED: the IN does not hold exactly the edges %s within 30s: %s\n" "$*" "$body"
    return 1
}
if [ "$fail" = 0 ]; then
    wait_registered "$(ini_get in httpPort)" "$(ini_get in cseName)" "$(ini_get mn-a cseID)" "$(ini_get mn-b cseID)" || fail=1
fi
echo "  logs: $RUN/<node>/logs/"
exit "$fail"
