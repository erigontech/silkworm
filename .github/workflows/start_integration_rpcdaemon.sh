#!/bin/bash

trap : SIGTERM SIGINT

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <data dir> <jwt_file>"
  exit 1
fi

echo "Silkworm RpcDaemon starting..."
./rpcdaemon --eth.addr 127.0.0.1:51515 --engine.addr 127.0.0.1:51516 --api admin,debug,eth,parity,erigon,trace,web3,txpool,ots,net --log.verbosity 1 --erigon_compatibility --jwt "$2" --skip_protocol_check --ws &


PID=$!

wait $PID

if [[ $? -gt 128 ]]
then
    kill $PID
fi

exit 0 
