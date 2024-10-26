#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <integration_dir> <jwt_file> <failed_tests_dir>"
  exit 1
fi

set +e # Disable exit on error

cd "$1" || exit 1
rm -rf ./mainnet/results/
 

# new API BlobBaseFee and BaseFee
# debug_traceTransaction: modify expected response according erigon(report evm error) and makes silkworm fix
# debug_traceCall/test_02.json: requests is_latest fix to support ethbackend 
# erigon_getHeaderByNumber: modify expected response according erigon and makes silkworm fix
# erigon_getHeaderByHash: modify expected response according erigon and makes silkworm fix
# debug_accountRange, debug_getModifiedAccountsm, debug_storageRangeAt, erigon_getBalanceChangesInBlock, ots_getTransactionBySenderAndNonce, ots_getContractCreator, ots_searchTransactionsAfter, ots_searchTransactionsBefore, erigon_getLatestLogs, eth_getLogs: new algo using tkv
# trace_rawTransaction: different implementation
# trace_replayTransaction/trace_replyBlockTransaction: have differente response with silkworm but should be rpcdaemon problems (to be analized)

python3 ./run_tests.py --continue --blockchain mainnet --jwt "$2" --display-only-fail --port 51515 -x \
debug_accountRange,\
debug_getModifiedAccounts,\
debug_storageRangeAt,\
debug_traceCall/test_02.json,\
debug_traceTransaction,\
engine_,\
erigon_getBalanceChangesInBlock,\
erigon_getHeaderByHash,\
erigon_getHeaderByNumber,\
erigon_getLatestLogs,\
eth_getLogs,\
eth_getBalance/test_05.json,\
ots_getTransactionBySenderAndNonce,\
ots_getContractCreator,\
ots_hasCode,\
ots_searchTransactionsAfter,\
ots_searchTransactionsBefore,\
parity_listStorageKeys/test_12.json,\
trace_rawTransaction --transport_type http,websocket

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


