#!/bin/bash

set -e
set -o pipefail

script_dir=$(dirname "${BASH_SOURCE[0]}")
project_dir="$script_dir/../.."

read -r -d '' commands << EOF
s/log::Trace()/SILK_TRACE/
s/log::Debug()/SILK_DEBUG/
s/log::Info()/SILK_INFO/
s/log::Warning()/SILK_WARN/
s/log::Error()/SILK_ERROR/
s/log::Critical()/SILK_CRIT/
s/log::Trace(/SILK_TRACE_M(/
s/log::Debug(/SILK_DEBUG_M(/
s/log::Info(/SILK_INFO_M(/
s/log::Warning(/SILK_WARN_M(/
s/log::Error(/SILK_ERROR_M(/
s/log::Critical(/SILK_CRIT_M(/
EOF

for dir in "$project_dir/cmd" "$project_dir/silkworm"
do
	find "$dir" -name '*.cpp' -or -name '*.hpp' | xargs -L1 sed -e "$commands" -i ''
done
