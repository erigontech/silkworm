#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <integration_dir> <jwt_file> <failed_tests_dir>"
  exit 1
fi

set +e # Disable exit on error

cd "$1" || exit 1
rm -rf ./mainnet/results/
 
# eth_getBlockReceipts/test_07.json new blobFields   
# debug_accountRange: new algo using TKV
# debug_getModifiedAccounts: new algo using TKV
# debug_storageRangeAt: new algo using TKV
# debug_traceCall/test_02.json: requested is_latest fix to support ethbackend
# erigon_getBalanceChangesInBlock: new algo using TKV
# erigon_getLatestLogs: new algo using TKV
# eth_getLogs: new algo using TKV
# ots_getContractCreator: new algo using TKV
# ots_getTransactionBySenderAndNonce/test_04.json: erigon3 bug in limit and page_size management in IndexRangeQuery query
# ots_getTransactionBySenderAndNonce/test_07.json: erigon3 bug in limit and page_size management in IndexRangeQuery query
# ots_searchTransactionsAfter: new algo using TKV
# ots_searchTransactionsBefore: new algo using TKV
# parity_listStorageKeys/test_12.json: fix required
# trace_rawTransaction: different implementation
# trace_replayTransaction/trace_replyBlockTransaction: silkworm has different response with erigon3 but could be erigon3 problem (to be analyzed)

python3 ./run_tests.py --continue --blockchain mainnet --jwt "$2" --display-only-fail --json-diff --port 51515 --transport_type http,websocket -x \
debug_accountRange,\
debug_getModifiedAccounts,\
debug_storageRangeAt,\
debug_traceBlockByHash/test_05,\
debug_traceBlockByHash/test_08,\
debug_traceBlockByHash/test_09,\
debug_traceBlockByHash/test_10,\
debug_traceBlockByHash/test_11,\
debug_traceBlockByHash/test_12,\
debug_traceCall/test_02.json,\
debug_traceTransaction/test_25.json,\
debug_traceTransaction/test_36.json,\
debug_traceTransaction/test_43.json,\
debug_traceTransaction/test_62.json,\
debug_traceTransaction/test_74.tar,\
debug_traceTransaction/test_75.tar,\
debug_traceTransaction/test_77.json,\
debug_traceTransaction/test_90.tar,\
debug_traceTransaction/test_91.tar,\
debug_traceTransaction/test_92.tar,\
debug_traceTransaction/test_96.json,\
engine_,\
erigon_getBalanceChangesInBlock,\
erigon_getLatestLogs,\
eth_getBlockReceipts/test_07.json,\
eth_getLogs,\
ots_getTransactionBySenderAndNonce/test_04.json,\
ots_getTransactionBySenderAndNonce/test_07.json,\
ots_getContractCreator,\
ots_searchTransactionsAfter,\
ots_searchTransactionsBefore,\
parity_listStorageKeys/test_12.json,\
trace_rawTransaction

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
