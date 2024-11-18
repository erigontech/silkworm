#!/bin/bash

set -e
set -o pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <rpcdaemon_pid>"
  exit 1
fi

# Clean up rpcdaemon process if it's still running
if kill -0 "$RPC_DAEMON_PID" 2> /dev/null; then
   echo "Silkworm RpcDaemon stopping..."
   kill "$RPC_DAEMON_PID"
   echo "Silkworm RpcDaemon stopped"
else
   echo "Silkworm RpcDaemon has already terminated"
fi
