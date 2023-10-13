#!/bin/bash

# $1 - compiler ID: gcc or clang
# $2 - compiler version

function install_gcc {
    GCC_VERSION="$1"
    echo "Installing GCC $GCC_VERSION..."

    sudo apt-get update
    sudo apt-get install -y gcc-$GCC_VERSION g++-$GCC_VERSION
    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-$GCC_VERSION 100 --slave /usr/bin/g++ g++ /usr/bin/g++-$GCC_VERSION
}

# libc++ is an alternative standard library needed for coroutines support on Clang
# https://libcxx.llvm.org
function install_clang {
	CLANG_VERSION="$1"
    echo "Installing clang $CLANG_VERSION..."

	sudo apt-get update

	if [[ "$CLANG_VERSION" == "16" ]]
	then
		apt-get install -y clang-16 lldb-16 lld-16 clangd-16 clang-tidy-16 clang-format-16 clang-tools-16 llvm-16-dev lld-16 lldb-16 llvm-16-tools libomp-16-dev libc++-16-dev libc++abi-16-dev libclang-common-16-dev libclang-16-dev libclang-cpp16-dev libunwind-16-dev
	else
		sudo apt-get install -y llvm-$CLANG_VERSION libc++-$CLANG_VERSION-dev libc++abi-$CLANG_VERSION-dev clang-$CLANG_VERSION
	fi
	
	sudo ln -sfv /usr/bin/clang-$CLANG_VERSION /usr/bin/clang
	sudo ln -sfv /usr/bin/clang++-$CLANG_VERSION /usr/bin/clang++
	sudo update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100
	sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100
	sudo update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-$CLANG_VERSION 100
	sudo update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-$CLANG_VERSION 100
}

if [[ -n "$1" ]]	
then
	compiler_id="$1"
else
	echo "Pass a required compiler ID parameter: gcc or clang"
	exit 1
fi

if [[ -n "$2" ]]	
then
	version="$2"
else
	echo "Pass a required compiler version parameter"
	exit 1
fi

case "$compiler_id" in
	gcc)
		install_gcc "$version"
		;;
	clang)		
		install_clang "$version"
		;;
esac
