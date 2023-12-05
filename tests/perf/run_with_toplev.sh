#!/bin/bash

sudo toplev --core S0-C0 -l3 -v --no-desc taskset -c 0 build_gcc_release/cmd/rpcdaemon --target localhost:9090
