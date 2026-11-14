#!/bin/sh
# Trace the C library as an additional module (first seed, angr) to test whether
# parsing loops that compare through libc string functions become visible.
# Usage: [THRESHOLD=N] run_libc.sh [TARGETS]
# Results in eval/results/libc/<target>/ or eval/results/libc-t<N>/<target>/
cd "$(dirname "$0")"
mkdir -p results/logs
TARGETS=${1:-"proftpd-1.3.8 proftpd lightftp pureftpd bftpd"}
THRESHOLD=${THRESHOLD:-1000}
OUT=libc; [ "$THRESHOLD" != 1000 ] && OUT="libc-t$THRESHOLD"
export OUT THRESHOLD
for t in $TARGETS; do echo "$t"; done | xargs -P "${JOBS:-3}" -L 1 sh -c '
  docker run --rm --cpus 2 --memory 6g --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD:/opt/synoptic/eval" -w /opt/synoptic synoptic-eval:latest \
    python3 eval/run_target.py "$0" first "eval/results/$OUT/$0" --engine angr --threshold "$THRESHOLD" \
      --modules /lib/x86_64-linux-gnu/libc.so.6 > "results/logs/$OUT-$0.log" 2>&1'
