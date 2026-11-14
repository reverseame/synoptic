#!/bin/sh
# Run the quantitative evaluation end to end. Results go to eval/results/.
# Requires the images built by eval/build.sh and eval/baselines/Dockerfile.
set -u
cd "$(dirname "$0")"
EVAL=$PWD
mkdir -p results/logs results/runs results/baselines
RUN="docker run --rm --cpus 2 --memory 6g --cap-add SYS_PTRACE --security-opt seccomp=unconfined -v $EVAL:/opt/synoptic/eval -w /opt/synoptic"

TARGETS=${TARGETS:-"proftpd-1.3.8 proftpd lightftp pureftpd bftpd"}
CONDITIONS=${CONDITIONS:-"first all"}

$RUN synoptic-eval:latest python3 eval/ground_truth.py eval/results/ground_truth.json

for t in $TARGETS; do
  for c in $CONDITIONS; do
    echo "== $t $c"
    $RUN synoptic-eval:latest python3 eval/run_target.py "$t" "$c" "eval/results/runs/$t/$c" \
      > "results/logs/$t-$c.log" 2>&1 || echo "   failed (see results/logs/$t-$c.log)"
  done
done
case " $TARGETS " in *" proftpd-1.3.8 "*)
  $RUN synoptic-eval:latest python3 eval/run_target.py proftpd-1.3.8 paper eval/results/runs/proftpd-1.3.8/paper \
    > results/logs/proftpd-1.3.8-paper.log 2>&1 || echo "   paper session failed";;
esac

$RUN -w /opt/synoptic/eval synoptic-eval:latest python3 capture_pcaps.py results/pcaps $TARGETS > results/logs/capture.log 2>&1

for t in $TARGETS; do
  port=21; [ "$t" = lightftp ] && port=2200
  docker run --rm --cpus 2 --memory 4g -v "$EVAL:/eval" synoptic-baselines:latest \
    python3 /eval/baselines/run_format_baselines.py "/eval/results/pcaps/$t.pcap" "$port" "/eval/results/baselines/$t.json" \
    > "results/logs/baselines-$t.log" 2>&1 || echo "   NEMESYS/Netzob failed for $t"
  docker run --rm --cpus 2 --memory 4g -v "$EVAL:/eval" synoptic-netplier:latest \
    python3 /eval/baselines/run_netplier.py "/eval/results/pcaps/$t.pcap" "$port" "/eval/results/baselines/$t-netplier.json" \
    > "results/logs/netplier-$t.log" 2>&1 || echo "   NetPlier failed for $t"
done
