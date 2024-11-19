#!/bin/bash

set -e
set -o pipefail

while [ True ]; do
if [ "$1" = "--refresh-cache" -o "$1" = "-r" ]; then
    RENEW=1
    shift 1
else
    break
fi
done

if (( $# != 1 )); then
    echo "Usage: $0 [--refresh-cache|-r] <branch>"
    exit 1
fi

BRANCH=$1

if [ -z "$RENEW" ]; then
    echo docker build --tag silkworm-clang:16 --progress=plain --build-arg="CACHEBUST=$(date +%s)" --build-arg="BRANCH=$BRANCH" -f ./Dockerfile ../..
else    
    echo docker build --tag silkworm-clang:16 --progress=plain --no-cache --build-arg="BRANCH=$BRANCH" -f ./Dockerfile ../..
fi

echo docker rm -f $(docker ps -aq --filter name=silkworm-clang-16)
echo docker run --name silkworm-clang-16 -d -t silkworm-clang:16