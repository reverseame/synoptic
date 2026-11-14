#!/bin/sh
# Sensitivity of the vocabulary results to the pintool spatial threshold.
# Usage: run_sensitivity.sh [TARGETS] ; results in eval/results/sensitivity/<target>-t<N>/
cd "$(dirname "$0")"
mkdir -p results/logs
TARGETS=${1:-"proftpd proftpd-1.3.8"}
THRESHOLDS=${THRESHOLDS:-"500 2000 5000 10000"}
for t in $TARGETS; do
  for n in $THRESHOLDS; do
    echo "$t $n"
  done
done | xargs -P "${JOBS:-2}" -L 1 sh -c '
  docker run --rm --cpus 2 --memory 6g --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD:/opt/synoptic/eval" -w /opt/synoptic synoptic-eval:latest \
    python3 eval/run_target.py "$0" first "eval/results/sensitivity/$0-t$1" --engine angr --threshold "$1" \
    > "results/logs/sensitivity-$0-t$1.log" 2>&1'
