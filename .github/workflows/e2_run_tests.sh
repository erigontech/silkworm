:
python3 ./run_tests.py --continue --blockchain mainnet --jwt $1 --display-only-fail --port 8545 -x admin_,eth_mining,eth_getWork,eth_coinbase,eth_createAccessList/test_16.json,engine_,net_,web3_,txpool_,eth_submitWork,eth_submitHashrate,eth_protocolVersion,erigon_nodeInfo --transport_type http,websocket
exit $?
