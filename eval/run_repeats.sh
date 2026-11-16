#!/bin/sh
# Repeat the vocabulary and format measurements (angr, both seed conditions, and the walk-through
# session) to measure run-to-run variability. The first repetition is eval/results itself.
# Usage: run_repeats.sh [REPETITIONS] ; results in eval/results/repeats/r<N>/ with the layout of
# eval/results (ground_truth.json, runs/, pcaps/, baselines/), scored into scores.txt.
set -u
cd "$(dirname "$0")"
EVAL=$PWD
TARGETS=${TARGETS:-"proftpd-1.3.8 proftpd lightftp pureftpd bftpd exim live555"}
for r in ${1:-2 3}; do
  out=results/repeats/r$r
  mkdir -p "$out/logs" "$out/baselines"
  cp results/ground_truth.json "$out/"
  {
    for t in $TARGETS; do
      for c in first all; do echo "$t $c"; done
    done
    echo "proftpd-1.3.8 paper"
  } | OUT=$out xargs -P "${JOBS:-3}" -L 1 sh -c '
    docker run --rm --cpus 2 --memory 6g --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
      -v "$PWD:/opt/synoptic/eval" -w /opt/synoptic synoptic-eval:latest \
      python3 eval/run_target.py "$0" "$1" "eval/$OUT/runs/$0/$1-angr" --engine angr \
      > "$OUT/logs/$0-$1-angr.log" 2>&1'
  docker run --rm -v "$EVAL:/opt/synoptic/eval" -w /opt/synoptic/eval synoptic-eval:latest \
    python3 capture_pcaps.py "$out/pcaps" $TARGETS > "$out/logs/capture.log" 2>&1
  for t in $TARGETS; do
    case "$t" in lightftp) port=2200;; exim) port=25;; live555) port=8554;; *) port=21;; esac
    docker run --rm --cpus 2 --memory 4g -v "$EVAL:/eval" synoptic-baselines:latest \
      python3 /eval/baselines/run_format_baselines.py "/eval/$out/pcaps/$t.pcap" "$port" "/eval/$out/baselines/$t.json" \
      > "$out/logs/baselines-$t.log" 2>&1 || echo "NEMESYS/Netzob failed for $t"
    docker run --rm --cpus 2 --memory 4g -v "$EVAL:/eval" synoptic-netplier:latest \
      python3 /eval/baselines/run_netplier.py "/eval/$out/pcaps/$t.pcap" "$port" "/eval/$out/baselines/$t-netplier.json" \
      > "$out/logs/netplier-$t.log" 2>&1 || echo "NetPlier failed for $t"
  done
  docker run --rm -v "$EVAL:/eval" synoptic-eval:latest chown -R "$(id -u):$(id -g)" "/eval/$out"
  python3 score.py "$out" > "$out/scores.txt" 2>&1
done
