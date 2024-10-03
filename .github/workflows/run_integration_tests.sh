#!/bin/bash

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 Erigon2/Erigon3 <integration-dir> <jwt-file> <saved failed tests>"
  exit 1
fi

set +e # Disable exit on error
cd $2
rm -rf ./mainnet/results/
 
if [ $1 == 'Erigon2' ]; then
   python3 ./run_tests.py --continue --blockchain mainnet --jwt $3 --display-only-fail --port 8545 -x admin_,eth_mining,eth_getWork,eth_coinbase,eth_createAccessList/test_16.json,engine_,net_,web3_,txpool_,eth_submitWork,eth_submitHashrate,eth_protocolVersion,erigon_nodeInfo --transport_type http,websocket
else
   python3 ./run_tests.py --continue --blockchain mainnet --jwt $3 --display-only-fail --port 8545 -x engine_,\
debug_accountRange,\
debug_getModifiedAccounts,\
debug_storageRangeAt,\
erigon_getBalanceChangesInBlock,\
ots_getTransactionBySenderAndNonce,\
parity_listStorageKeys,\
ots_getContractCreator,\
erigon_getLatestLogs,\
eth_getLogs,\
erigon_getBlockReceiptsByBlockHash/test_05.json,\
eth_getBlockReceipts/test_04.json,\
ots_getBlockDetails/test_05.json,\
ots_getBlockDetailsByHash/test_03.json,\
ots_getBlockTransactions/test_04.json,\
ots_getBlockTransactions/test_07.json,\
ots_searchTransactionsAfter,\
ots_searchTransactionsBefore --transport_type http,websocket
fi

failed_test=$?

# Check test runner exit status
if [ $failed_test -eq 0 ]; then
    echo "tests completed successfully"
else
    echo "error detected during tests"

    # Save failed results to a directory with timestamp and commit hash
    cp -r $2/mainnet/results/ $4
fi
exit $failed_test

