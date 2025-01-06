#!/bin/bash

# $1 - compiler ID: gcc or clang
# $2 - compiler version

set -e
set -o pipefail

script_dir=$(dirname "${BASH_SOURCE[0]}")
project_dir="$script_dir/../.."

function install_gcc {
    GCC_VERSION="$1"
    echo "Installing GCC $GCC_VERSION..."

    sudo apt-get update
    sudo apt-get install -y g++-$GCC_VERSION
    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-$GCC_VERSION 100 \
    	--slave /usr/bin/g++ g++ /usr/bin/g++-$GCC_VERSION
    sudo update-alternatives --install /usr/bin/cc cc /usr/bin/gcc 100
    sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++ 100
    sudo update-alternatives --set gcc /usr/bin/gcc-$GCC_VERSION
    sudo update-alternatives --set cc /usr/bin/gcc
    sudo update-alternatives --set c++ /usr/bin/g++
}

# libc++ is an alternative standard library needed for coroutines support on Clang
# https://libcxx.llvm.org
function install_clang {
	CLANG_VERSION="$1"
    echo "Installing clang $CLANG_VERSION..."

	sudo apt-get update
	if apt-cache show clang-$CLANG_VERSION > /dev/null 2>&1
	then
		echo "Installing from the default apt repositories"
		sudo apt-get install -y clang-$CLANG_VERSION \
			libc++-$CLANG_VERSION-dev libc++abi-$CLANG_VERSION-dev \
			lld-$CLANG_VERSION
	else
		echo "Installing from apt.llvm.org using llvm.sh script"
		sudo "$project_dir/third_party/llvm/llvm.sh" $CLANG_VERSION
	fi

	sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-$CLANG_VERSION 100 \
		--slave /usr/bin/clang++ clang++ /usr/bin/clang++-$CLANG_VERSION \
		--slave /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-$CLANG_VERSION \
		--slave /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-$CLANG_VERSION
    sudo update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100
    sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100
    sudo update-alternatives --set clang /usr/bin/clang-$CLANG_VERSION
    sudo update-alternatives --set cc /usr/bin/clang
    sudo update-alternatives --set c++ /usr/bin/clang++

	# alias gcc to clang
	# this is useful for scripts having gcc hardcoded (such as GMP autotools build)
    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/clang 10 \
    	--slave /usr/bin/g++ g++ /usr/bin/clang++
	sudo update-alternatives --set gcc /usr/bin/clang
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

update-alternatives --display cc
update-alternatives --display c++
update-alternatives --display gcc
