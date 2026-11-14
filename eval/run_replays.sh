#!/bin/sh
# Replay stage of the case study (ProFTPD 1.3.8, 2023 server configuration), in parallel:
#   2023-fixed-acceptance  original replayer, corrected resp_is_ok only (synoptic-eval:replay-original)
#   2023-fixed             current replayer, on the 2023 fsm.json
#   rerun-fixed            current replayer, on the fsm.json of our rerun of the case-study session
# The unmodified 2023 replay (2023-original) is run separately with the replay-original image.
# Results in eval/results/replay/<name>/, logs in eval/results/logs/replay-<name>.log
cd "$(dirname "$0")"
mkdir -p results/logs
run() {
  name=$1 image=$2 fsm=$3; shift 3
  docker run --rm --cpus 2 --memory 4g -v "$PWD:/opt/synoptic/eval" -w /opt/synoptic "$image" \
    sh -c "mkdir -p /usr/local/var && python3 eval/run_replay.py proftpd-1.3.8 $fsm eval/results/replay/$name \
           --conf /opt/synoptic/eval/replay/proftpd-2023.conf $*" > "results/logs/replay-$name.log" 2>&1
}
run 2023-fixed-acceptance synoptic-eval:replay-original eval/replay/2023/fsm.json --fixed-acceptance &
run 2023-fixed synoptic-eval:latest eval/replay/2023/fsm.json &
run rerun-fixed synoptic-eval:latest eval/results/runs/proftpd-1.3.8/paper-angr/fsm.json &
wait
