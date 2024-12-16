#!/bin/bash

script_dir=$(dirname "${BASH_SOURCE[0]}")
project_dir="$script_dir/.."
build_dir="$1"

if [[ -z "$build_dir" ]]
then
	build_dir="$project_dir/build"
fi

cat << EOF > "$script_dir/conan_quiet.cmake"
# Reduce verbosity of CMakeDeps conan generator
# do not edit, regenerate with conan_quiet.sh

EOF

grep -R FIND_QUIETLY "$build_dir/conan2" | sed -E 's/.+\((.+)\)/set(\1 YES)/' >> "$script_dir/conan_quiet.cmake"
