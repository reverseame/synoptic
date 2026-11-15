#!/bin/sh
# Vocabulary runs without the summaries of calls into untraced code (angr, both seed conditions).
# Usage: run_nosummaries.sh [TARGETS] ; results in eval/results/runs-nosummaries/<target>/<condition>-angr/
cd "$(dirname "$0")"
mkdir -p results/logs
TARGETS=${1:-"proftpd-1.3.8 proftpd lightftp pureftpd bftpd exim live555"}
for t in $TARGETS; do
  for c in first all; do
    echo "$t $c"
  done
done | xargs -P "${JOBS:-3}" -L 1 sh -c '
  docker run --rm --cpus 2 --memory 6g --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD:/opt/synoptic/eval" -w /opt/synoptic synoptic-eval:latest \
    python3 eval/run_target.py "$0" "$1" "eval/results/runs-nosummaries/$0/$1-angr" --engine angr --no-summaries \
    > "results/logs/nosummaries-$0-$1.log" 2>&1'
