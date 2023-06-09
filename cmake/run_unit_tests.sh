#!/bin/sh

if test `uname -s` = Linux
then
    ulimit -s unlimited
fi

if test `uname -s` = Darwin
then
    ulimit -n 1024
fi

script_dir=`dirname "$0"`

cmake "-DSILKWORM_BUILD_DIR=$1" "-DSILKWORM_CLANG_COVERAGE=$2" -P "$script_dir/run_unit_tests.cmake"
