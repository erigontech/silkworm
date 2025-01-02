#!/bin/bash

set -e
set -o pipefail

if test "$(uname -s)" = Linux
then
    ulimit -s unlimited
fi

script_dir=$(dirname "$0")

cmake "-DSILKWORM_BUILD_DIR=$1" "-DSILKWORM_CLANG_COVERAGE=$2" "-DSILKWORM_SANITIZE=$3" "-SILKWORM_PROJECT_DIR=$4" -P "$script_dir/run_unit_tests.cmake" \
	| grep -Ev '^(Randomness|RNG seed|============================)'
