#!/bin/bash

set -e
set -o pipefail

clion="/Applications/CLion.app"
clion_tidy="$clion/Contents/bin/clang/mac/aarch64/clang-tidy"
clion_builtin_includes="$(dirname "$clion_tidy")/include"

script_dir=$(dirname "${BASH_SOURCE[0]}")
project_dir=$(realpath "$script_dir/../..")
build_dir="$project_dir/build"
base_commit=master

if [[ -n "$1" ]]
then
	base_commit="$1"
fi

if [[ -n "$2" ]]
then
	build_dir="$2"
fi

if which clang-tidy > /dev/null
then
	tidy=clang-tidy
	builtin_includes=/usr/include
elif [[ -x "$clion_tidy" ]]
then
	tidy="$clion_tidy"
	builtin_includes="$clion_builtin_includes"
else
	echo "clang-tidy not found" >&2
	exit 1
fi

args=(
	-clang-tidy-binary "$tidy"
	-p 1
	-exclude "(mock_block_exchange.hpp|mock_execution_client.hpp|.pb.h|mock_back_end.hpp|remote_backend)"
	-j 6
	-timeout 60
	-config-file "$project_dir/.clang-tidy"
	-use-color
	-path "$build_dir"
)

git diff "$base_commit" | "$script_dir/clang-tidy-diff.py" "${args[@]}"
