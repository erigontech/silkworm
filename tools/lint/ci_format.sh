#!/bin/bash

set -e
set -o pipefail

pip3 install --user --no-warn-script-location cmake-format==0.6.13 pyyaml
install_path="$(python3 -m site --user-base)/bin"
export "PATH=$install_path:$PATH"

make fmt

if ! git diff --exit-code
then
	commit_message="make fmt"
	head_commit_message="$(git log -1 --pretty=%B)"

	if [[ "$head_commit_message" == "$commit_message" ]]
	then
		echo "The formatting style is not compliant, although it was formatted. Try to run 'make fmt' locally and push the changes."
		exit 1
	else
		git config user.name GitHub
		git config user.email noreply@github.com
		git commit --all --message="$commit_message"
		git config push.autoSetupRemote true
		git push

		echo "The formatting style was not compliant, but it is fixed now. A new workflow will start soon, wait for it..."
		exit 2
	fi
fi
