#!/bin/sh
# Run the quantitative evaluation end to end. Results go to eval/results/.
# Requires the images built by eval/build.sh and eval/baselines/build.sh.
# Environment overrides: TARGETS, CONDITIONS, ENGINES, JOBS (parallel Synoptic runs).
set -u
cd "$(dirname "$0")"
EVAL=$PWD
mkdir -p results/logs results/runs results/baselines

TARGETS=${TARGETS:-"proftpd-1.3.8 proftpd lightftp pureftpd bftpd"}
CONDITIONS=${CONDITIONS:-"first all"}
ENGINES=${ENGINES:-"angr binsec"}
JOBS=${JOBS:-2}

docker run --rm -v "$EVAL:/opt/synoptic/eval" -w /opt/synoptic synoptic-eval:latest \
  python3 eval/ground_truth.py eval/results/ground_truth.json

# Synoptic runs: one container per (target, condition, engine), JOBS at a time
{
  for t in $TARGETS; do
    for c in $CONDITIONS; do
      for e in $ENGINES; do echo "$t $c $e runs/$t/$c-$e"; done
    done
  done
  case " $TARGETS " in *" proftpd-1.3.8 "*)
    for e in $ENGINES; do echo "proftpd-1.3.8 paper $e runs/proftpd-1.3.8/paper-$e"; done;;
  esac
} | xargs -P "$JOBS" -L 1 ./run_one.sh

# Network traces for the baselines (no Pin)
docker run --rm -v "$EVAL:/opt/synoptic/eval" -w /opt/synoptic/eval synoptic-eval:latest \
  python3 capture_pcaps.py results/pcaps $TARGETS > results/logs/capture.log 2>&1

for t in $TARGETS; do
  port=21; [ "$t" = lightftp ] && port=2200
  docker run --rm --cpus 2 --memory 4g -v "$EVAL:/eval" synoptic-baselines:latest \
    python3 /eval/baselines/run_format_baselines.py "/eval/results/pcaps/$t.pcap" "$port" "/eval/results/baselines/$t.json" \
    > "results/logs/baselines-$t.log" 2>&1 || echo "NEMESYS/Netzob failed for $t"
  docker run --rm --cpus 2 --memory 4g -v "$EVAL:/eval" synoptic-netplier:latest \
    python3 /eval/baselines/run_netplier.py "/eval/results/pcaps/$t.pcap" "$port" "/eval/results/baselines/$t-netplier.json" \
    > "results/logs/netplier-$t.log" 2>&1 || echo "NetPlier failed for $t"
done

docker run --rm -v "$EVAL:/eval" synoptic-eval:latest chown -R "$(id -u):$(id -g)" /eval/results
python3 score.py results | tee results/scores.txt
