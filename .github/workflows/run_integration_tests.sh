#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <integration_dir> <jwt_file> <failed_tests_dir>"
  exit 1
fi

# TODO: why is this disabled?
set +e # Disable exit on error
set -o pipefail

cd "$1" || exit 1
rm -rf ./mainnet/results/
 
# eth_getLogs: waiting erigon fix on wrong FirstLogIndex in ReceiptsDomain
# debug_traceBlockByNumber[24-28]: response different wrt erigon
python3 ./run_tests.py --continue --blockchain mainnet --jwt "$2" --display-only-fail --json-diff --port 51515 --transport_type http,websocket -x \
debug_accountRange,\
debug_getModifiedAccountsBy,\
debug_storageRangeAt,\
debug_traceBlockByHash/test_10,\
debug_traceBlockByNumber/test_10,\
debug_traceBlockByNumber/test_24,\
debug_traceBlockByNumber/test_25,\
debug_traceBlockByNumber/test_26,\
debug_traceBlockByNumber/test_27,\
debug_traceBlockByNumber/test_28,\
debug_traceCall/test_21,\
debug_traceTransaction/test_25,\
debug_traceTransaction/test_36,\
debug_traceTransaction/test_43,\
debug_traceTransaction/test_62,\
debug_traceTransaction/test_74,\
debug_traceTransaction/test_75,\
debug_traceTransaction/test_77,\
debug_traceTransaction/test_90,\
debug_traceTransaction/test_91,\
debug_traceTransaction/test_92,\
debug_traceTransaction/test_96,\
engine_,\
eth_getLogs/test_16,\
eth_getLogs/test_17,\
eth_getLogs/test_18,\
eth_getLogs/test_19,\
eth_getLogs/test_20,\
parity_listStorageKeys,\
trace_replayBlockTransactions/test_29,\
trace_transaction/test_44,\
trace_transaction/test_47

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
