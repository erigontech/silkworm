#!/bin/bash

RATE=${1:-200}
DURATION=${2:-30}
TIMEOUT=${3:-300}
VEGETA_BODY_FILE=${4:-/tmp/turbo_geth_stress_test/vegeta_geth_eth_getLogs.txt}

cat $VEGETA_BODY_FILE |
    vegeta attack -keepalive -rate=${RATE} -format=json -duration=${DURATION}s -timeout=${TIMEOUT}s |
        vegeta report -type=text > getLogs_${RATE}qps_${DURATION}s_silkrpc_perf.hrd
