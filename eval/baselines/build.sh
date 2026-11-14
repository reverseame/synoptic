#!/bin/sh
# Build the baseline images (NEMESYS/Netzob and NetPlier). Logs go to eval/results/.
cd "$(dirname "$0")"
mkdir -p ../results
docker build --memory 4g -t synoptic-baselines:latest -f Dockerfile . > ../results/baselines-build.log 2>&1
echo "finished $?" >> ../results/baselines-build.log
docker build --memory 4g -t synoptic-netplier:latest -f netplier.Dockerfile . > ../results/netplier-build.log 2>&1
echo "finished $?" >> ../results/netplier-build.log
