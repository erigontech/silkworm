:
set +e # Disable exit on error
cd $1
rm -rf ./mainnet/results/
 
python3 ./run_tests.py --continue --blockchain mainnet --jwt $2 --display-only-fail --port 8545 -x admin_,eth_mining,eth_getWork,eth_coinbase,eth_createAccessList/test_16.json,engine_,net_,web3_,txpool_,eth_submitWork,eth_submitHashrate,eth_protocolVersion,erigon_nodeInfo --transport_type http,websocket
exit_status=$?

# Check test runner exit status
if [ $test_exit_status -eq 0 ]; then
    echo "tests completed successfully"
else
    echo "error detected during tests"
fi
exit $exit_status

