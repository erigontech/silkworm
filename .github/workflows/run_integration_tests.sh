#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <integration_dir> <jwt_file> <failed_tests_dir>"
  exit 1
fi

set +e # Disable exit on error

cd "$1" || exit 1
rm -rf ./mainnet/results/
 
python3 ./run_tests.py --continue --blockchain mainnet --jwt "$2" --display-only-fail --port 51515 --transport_type http,websocket \
-x engine_,\
erigon_getHeaderByHash/test_05.json,\
debug_accountAt,\
debug_accountRange,\
debug_getModifiedAccounts,\
debug_storageRangeAt,\
debug_traceBlockByHash,\
debug_traceCall/test_02.json,\
eth_createAccessList/test_16.json,\
eth_estimateGas,\
eth_getBalance,\
eth_getBlockByHash,\
eth_getBlockTransactionCountByHash,\
eth_getCode,\
eth_getLogs,\
eth_getRawTransactionByBlockHashAndIndex,\
eth_getStorageAt/test_01.json,\
eth_getStorageAt/test_02.json,\
eth_getStorageAt/test_03.json,\
eth_getTransactionByBlockHashAndIndex,\
eth_getTransactionCount/test_01.json,\
eth_getTransactionCount/test_06.json,\
eth_getUncleCountByBlockHash,\
erigon_getBlockReceiptsByBlockHash,\
erigon_getHeaderByHash,\
erigon_getLatestLogs,\
erigon_getLogsByHash,\
erigon_getBalanceChangesInBlock,\
ots_getTransactionBySenderAndNonce,\
ots_getContractCreator,\
ots_hasCode,\
ots_searchTransactionsAfter,\
ots_searchTransactionsBefore,\
parity_listStorageKeys/test_12.json \
txpool_content

failed_test=$?

# Check test runner exit status
if [ $failed_test -eq 0 ]; then
    echo "tests completed successfully"
else
    echo "error detected during tests"

    # Save failed results to a directory with timestamp and commit hash
    cp -r "$1"/mainnet/results/ "$3"
fi

exit $failed_test


