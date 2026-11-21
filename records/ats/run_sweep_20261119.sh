#!/usr/bin/env bash
# Full ETSI MEC ATS sweep (55 suites) against our candidates, 2026-11-19. No phone. The two lab services that hold
# ports the sweep needs (mec012 :8085, mec013_look :8101) are stopped by their exact pids first and started again
# afterwards from the same directory with the same command; everything else is left as it is.
set -uo pipefail
R=/home/edgefollow/edgefollow; OUTD=/home/edgefollow/estimed-run/ats; PY=/home/edgefollow/edgefollow-lab/.venv/bin/python
cd $R
echo "start $(date -u +%FT%TZ) commit $(git rev-parse --short HEAD) dirty-tracked $(git status --porcelain | grep -vc '^??')"
echo "ATS reference: $(git -C /home/edgefollow/etsi-forge-ats-reference rev-parse --short HEAD) status: $(git -C /home/edgefollow/etsi-forge-ats-reference status --porcelain | tr '\n' ' ')"
for p in 8085 8101; do
  pid=$(ss -ltnp 2>/dev/null | awk -v p=":$p" '$4 ~ p"$" {print $NF}' | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
  [ -n "$pid" ] && echo "stopping :$p pid $pid ($(ps -o args= -p $pid))" && kill -TERM $pid
done
sleep 3
bash sweep_all.sh $OUTD/sweep_2026-11-19.txt
echo "sweep exit $? at $(date -u +%FT%TZ)"
for s in mec012/candidate.py mec013_look/candidate.py; do (setsid $PY $s > $OUTD/restart_$(dirname $s).log 2>&1 < /dev/null &); done
sleep 6
for u in "8085/rni/v2/subscriptions" "8101/location/v3/queries/users"; do echo "after: :${u%%/*} -> $(curl -s -o /dev/null --max-time 4 -w '%{http_code}' http://127.0.0.1:$u)"; done
echo "ATS reference after: $(git -C /home/edgefollow/etsi-forge-ats-reference status --porcelain | tr '\n' ' ')"
