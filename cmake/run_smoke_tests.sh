#!/bin/bash

set -e
set -o pipefail

if test `uname -s` = Linux
then
    ulimit -s unlimited
fi

script_dir=`dirname "$0"`

cmake "-DSILKWORM_BUILD_DIR=$1" -P "$script_dir/run_smoke_tests.cmake"
