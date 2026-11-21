#!/usr/bin/env bash
# Stop the ESTIMED oneM2M topology.
#
# Kills the recorded pid AND sweeps any CSE still holding a node's base directory,
# because an earlier generation left orphans that kept the ports and made every
# restart fail with "Port already in use" while health checks answered from the
# stale process.
#
# NEVER `pkill -f <pattern>`: this tool runs commands via `bash -c "<cmd>"`, so the
# pattern is in the invoking shell's own argv and pkill kills the shell instead of
# the target. That trap cost three runs in this session, and is recorded for the
# MEC candidates' CANDMARK tokens too (the marker argument ETSI's test-suite runner passes so it can find them).
set -uo pipefail

VENV=${VENV:-/home/edgefollow/estimed-venv}
RUN=${RUN:-/home/edgefollow/estimed-run}

kill_matching() {   # substring -> kills every acmecse process whose cmdline has it
    local want=$1 self=$$ n=0
    for p in /proc/[0-9]*; do
        local pid=${p#/proc/}
        [ "$pid" = "$self" ] && continue
        local c; c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
        case "$c" in *zsh*|*bash*) continue;; esac
        case "$c" in
            *"$VENV/bin/acmecse"*"$want"*) kill -TERM "$pid" 2>/dev/null && n=$((n+1));;
        esac
    done
    echo "$n"
}

for name in mn-b mn-a in; do
    n=$(kill_matching "$RUN/$name")
    rm -f "$RUN/$name/cse.pid"
    printf "  %-6s %s process(es) stopped\n" "$name" "$n"
done

sleep 3
# Anything of THIS run still alive gets SIGKILL, so a following start never hits a held port. Only processes under
# $RUN: the sweep used to kill every acmecse on the machine, another lab's included (fixed 2026-10-29).
left=0
for p in /proc/[0-9]*; do
    pid=${p#/proc/}; [ "$pid" = "$$" ] && continue
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
    case "$c" in *zsh*|*bash*) continue;; esac
    case "$c" in *"$VENV/bin/acmecse"*"$RUN/"*) kill -9 "$pid" 2>/dev/null; left=$((left+1));; esac
done
[ "$left" -gt 0 ] && echo "  force-killed $left remaining"
exit 0
