#!/bin/bash

set -e
set -o pipefail

clion="/Applications/CLion.app"
clion_tidy="$clion/Contents/bin/clang/mac/aarch64/bin/clang-tidy"
clion_builtin_includes="$clion/Contents/bin/lldb/mac/aarch64/LLDB.framework/Resources/Clang/include"

function install_clion_tidy {
	target_dir="$1"
	version=$("$clion_tidy" --version | grep version | awk '{ print($NF) }' | cut -d '.' -f 1)
	mkdir -p "$target_dir/bin"
	cp "$clion_tidy" "$target_dir/bin"
	mkdir -p "$target_dir/lib/clang/$version"
	cp -R "$clion_builtin_includes" "$target_dir/lib/clang/$version"
}

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
elif [[ -d "$clion" ]]
then
	install_clion_tidy "$build_dir/tidy"
	tidy="$build_dir/tidy/bin/clang-tidy"
else
	echo "clang-tidy not found" >&2
	exit 1
fi

args=(
	-clang-tidy-binary "$tidy"
	-p 1
	-exclude "(\\.hpp|\\.pb\\.)"
	-j 6
	-timeout 60
	-config-file "$project_dir/.clang-tidy"
	-use-color
	-path "$build_dir"
)

git diff "$base_commit" | "$script_dir/clang-tidy-diff.py" "${args[@]}"
