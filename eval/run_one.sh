#!/bin/sh
# Run one Synoptic analysis in the evaluation image.
# Usage: run_one.sh TARGET CONDITION ENGINE OUTDIR_UNDER_RESULTS
# Log: eval/results/logs/<TARGET>-<CONDITION>-<ENGINE>.log
cd "$(dirname "$0")"
mkdir -p results/logs
exec docker run --rm --cpus 2 --memory 6g --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
  -v "$PWD:/opt/synoptic/eval" -w /opt/synoptic synoptic-eval:latest \
  python3 eval/run_target.py "$1" "$2" "eval/results/$4" --engine "$3" > "results/logs/$1-$2-$3.log" 2>&1
