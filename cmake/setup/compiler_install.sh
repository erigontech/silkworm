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
	
	if [[ "$CLANG_VERSION" -ge 16 ]]
	then
		# Clang 16 and later versions have a different package repository
		# Get the latest installation script and execute
 		sudo rm -f llvm.sh
 		sudo wget https://apt.llvm.org/llvm.sh
		sudo chmod u+x llvm.sh
		sudo ./llvm.sh $CLANG_VERSION
		sudo apt-get install -y libc++-$CLANG_VERSION-dev libc++abi-$CLANG_VERSION-dev
		sudo ln -sfv /usr/bin/clang-$CLANG_VERSION /usr/bin/clang
		sudo ln -sfv /usr/bin/clang++-$CLANG_VERSION /usr/bin/clang++
		sudo update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100
		sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100
	else
		# Install Clang 15 and earlier versions using the default package repository
		sudo apt-get install -y llvm-$CLANG_VERSION libc++-$CLANG_VERSION-dev libc++abi-$CLANG_VERSION-dev clang-$CLANG_VERSION
		sudo ln -sfv /usr/bin/clang-$CLANG_VERSION /usr/bin/clang
		sudo ln -sfv /usr/bin/clang++-$CLANG_VERSION /usr/bin/clang++
		sudo update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100
		sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100
		sudo update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-$CLANG_VERSION 100
		sudo update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-$CLANG_VERSION 100
	fi
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
