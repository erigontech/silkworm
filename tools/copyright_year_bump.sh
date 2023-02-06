#!/bin/bash

scriptDir=$(dirname "$0")
repoDir="$scriptDir/.."

copyright=$(head "$repoDir/cmake/copyright.cmake" | grep "Copyright")

newYear=$(date '+%Y')
oldYear=$(($newYear - 1))

echo "updating $oldYear to $newYear"

oldCopyright=${copyright/[0-9][0-9][0-9][0-9]/$oldYear}
newCopyright=${copyright/[0-9][0-9][0-9][0-9]/$newYear}

echo "---$oldCopyright"
echo "+++$newCopyright"

cppFiles=$(cd "$repoDir" && cmake -P "cmake/copyright.cmake" --log-level VERBOSE | cut -c 3-)
cmakeFiles=$(find "$repoDir" \( -name '*.cmake' -or -name 'CMakeLists.txt' \) -not -path '*/build/*' -not -path '*/third_party/*')

newline=$'\n'
files="$cppFiles$newline$cmakeFiles"

echo "$files" | while read f
do
	sed -i '' "s/$oldCopyright/$newCopyright/g" "$f"
done

$(cd "$repoDir" && cmake -P "cmake/copyright.cmake")

git -C "$repoDir" grep "$oldCopyright"
