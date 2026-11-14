#!/bin/sh
# Build the evaluation image from the repository root. Log goes to eval/results/build.log.
cd "$(dirname "$0")/.."
mkdir -p eval/results
docker build --memory 6g -f eval/Dockerfile -t synoptic-eval:latest . > eval/results/build.log 2>&1
echo "build finished: $?" >> eval/results/build.log
