#!/bin/sh

if test `uname -s` = Linux
then
    ulimit -s unlimited
fi

script_dir=`dirname "$0"`

cmake "-DSILKWORM_BUILD_DIR=$1" "-DSILKWORM_CLANG_COVERAGE=$2" -P "$script_dir/run_unit_tests.cmake" \
	| grep -Ev '^(Randomness|RNG seed|============================)'
