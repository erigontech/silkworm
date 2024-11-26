#!/bin/bash

set -e
set -o pipefail

build_log="$1"

if [[ ! -f "$build_log" ]]
then
    echo "the build log file is not found at '$build_log'"
    exit 1
fi

function filter_warnings {
	grep "warning:" || true
}

warnings=$(cat "$build_log" | filter_warnings | sort | uniq)
warn_count=$(echo "$warnings" | wc -l)

echo "$warnings"
echo
echo "clang-tidy produced $warn_count warnings"
echo "see the build step output for more details"

if (( warn_count > 50 ))
then
    echo "go fix the warnings now!"
    exit 2
fi
