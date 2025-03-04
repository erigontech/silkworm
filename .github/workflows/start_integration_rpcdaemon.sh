#!/bin/bash

set -e
set -o pipefail

trap : SIGTERM SIGINT

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <data dir> <jwt_file>"
  exit 1
fi

echo "Silkworm RpcDaemon starting..."
./rpcdaemon --eth.addr 127.0.0.1:51515 --engine.addr 127.0.0.1:51516 --api admin,debug,eth,parity,erigon,trace,web3,txpool,ots,net --log.verbosity info --erigon_compatibility --datadir "$1" --jwt "$2" --ws &


PID=$!

wait $PID

if [[ $? -gt 128 ]]
then
    kill $PID
fi

exit 0 
