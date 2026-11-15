#!/bin/sh
# Replay stage on the ProFuzzBench servers, from the FSM of the first-seed angr run, against
# uninstrumented servers. Usage: run_server_replays.sh [TARGETS]
# Results in eval/results/replay/<target>-first/, logs in eval/results/logs/replay-<target>-first.log
cd "$(dirname "$0")"
mkdir -p results/logs results/replay
TARGETS=${1:-"lightftp pureftpd bftpd exim live555"}
for t in $TARGETS; do
  echo "$t"
done | xargs -P "${JOBS:-3}" -L 1 sh -c '
  rm -rf "results/replay/$0-first"
  docker run --rm --cpus 2 --memory 4g -v "$PWD:/opt/synoptic/eval" -w /opt/synoptic synoptic-eval:latest \
    python3 eval/run_replay.py "$0" "eval/results/runs/$0/first-angr/fsm.json" "eval/results/replay/$0-first" \
    > "results/logs/replay-$0-first.log" 2>&1'
