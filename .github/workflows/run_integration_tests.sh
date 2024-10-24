#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <integration_dir> <jwt_file> <failed_tests_dir>"
  exit 1
fi

set +e # Disable exit on error

cd "$1" || exit 1
rm -rf ./mainnet/results/
 
python3 ./run_tests.py --continue --blockchain mainnet --jwt "$2" --display-only-fail --port 51515 -x engine_,\
eth_getBalance,\
debug_traceCall/test_02.json,\
eth_getCode,\
ots_hasCode,\
eth_estimateGas,\
eth_getStorageAt/test_01.json,\
eth_getStorageAt/test_02.json,\
eth_getStorageAt/test_03.json,\
eth_getTransactionCount/test_01.json,\
eth_getTransactionCount/test_06.json,\
eth_createAccessList/test_16.json,\
erigon_getHeaderByHash/test_05.json,\
debug_traceCall/test_02.json,\
debug_accountRange,\
debug_getModifiedAccounts,\
debug_storageRangeAt,\
erigon_getBalanceChangesInBlock,\
ots_getTransactionBySenderAndNonce,\
parity_listStorageKeys,\
ots_getContractCreator,\
erigon_getLatestLogs,\
eth_getLogs,\
ots_searchTransactionsAfter,\
ots_searchTransactionsBefore,\
txpool_content --transport_type http,websocket

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


