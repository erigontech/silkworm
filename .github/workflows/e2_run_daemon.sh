#!/bin/bash
trap : SIGTERM SIGINT

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 Erigon2/Erigon3 <datadir> <jwtfile>"
  exit -1
fi

echo "Silkworm RpcDaemon starting..."
if [ $1 == 'Erigon2' ]; then
./rpcdaemon --datadir $2 --api admin,debug,eth,parity,erigon,trace,web3,txpool,ots,net --log.verbosity 1 --erigon_compatibility --jwt $3 --skip_protocol_check --ws &
else
./rpcdaemon --api admin,debug,eth,parity,erigon,trace,web3,txpool,ots,net --log.verbosity 1 --erigon_compatibility --jwt $2 --skip_protocol_check --ws &
fi

PID=$!

wait $PID

if [[ $? -gt 128 ]]
then
    kill $PID
fi

exit 0 
