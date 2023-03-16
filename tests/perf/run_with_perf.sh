#!/bin/bash

sudo perf stat --topdown -a -- taskset -c 0 build_gcc_release/cmd/silkrpcdaemon --target localhost:9090
