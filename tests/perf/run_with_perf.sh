#!/bin/bash

set -e
set -o pipefail

sudo perf stat --topdown -a -- taskset -c 0 build_gcc_release/cmd/rpcdaemon --target localhost:9090
