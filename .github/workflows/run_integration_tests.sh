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
debug_traceCall/test_02.json,\
debug_accountAt,\
debug_traceBlockByHash,\
erigon_getBlockReceiptsByBlockHash,\
erigon_getHeaderByHash,\
erigon_getLogsByHash,\
eth_getBlockByHash,\
eth_getBlockTransactionCountByHash,\
eth_getRawTransactionByBlockHashAndIndex,\
eth_getTransactionByBlockHashAndIndex,\
eth_getUncleCountByBlockHash,\
debug_accountRange,\
debug_getModifiedAccounts,\
debug_storageRangeAt,\
erigon_getBalanceChangesInBlock,\
ots_getTransactionBySenderAndNonce,\
ots_getContractCreator,\
erigon_getLatestLogs,\
eth_getLogs,\
txpool_content,\
ots_searchTransactionsAfter,\
ots_searchTransactionsBefore 

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


