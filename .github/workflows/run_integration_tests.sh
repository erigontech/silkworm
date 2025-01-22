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
 
python3 ./run_tests.py --continue --blockchain mainnet --jwt "$2" --display-only-fail --json-diff --port 51515 --transport_type http,websocket -x \
debug_traceBlockByHash/test_09,\
debug_traceBlockByHash/test_10,\
debug_traceBlockByNumber/test_09,\
debug_traceBlockByNumber/test_10,\
debug_traceBlockByNumber/test_29,\
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
trace_replayBlockTransactions/test_29,\
engine_,\
trace_filter/test_24.json,\
trace_replayTransaction/test_48.tar,\
trace_transaction/test_37.json

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
