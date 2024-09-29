:
./rpcdaemon --datadir $1 --api admin,debug,eth,parity,erigon,trace,web3,txpool,ots,net --log.verbosity 1 --erigon_compatibility --jwt $2 --skip_protocol_check --ws &
