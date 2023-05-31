# Silkworm - C++ Ethereum Execution Client

C++ implementation of the Ethereum Execution Layer (EL) protocol based on the [Erigon Thorax architecture].

[![CircleCI](https://circleci.com/gh/torquem-ch/silkworm.svg?style=shield)](https://circleci.com/gh/torquem-ch/silkworm)
[![macOS](https://github.com/torquem-ch/silkworm/actions/workflows/macOS.yml/badge.svg)](https://github.com/torquem-ch/silkworm/actions/workflows/macOS.yml)
[![Windows](https://github.com/torquem-ch/silkworm/actions/workflows/windows.yml/badge.svg)](https://github.com/torquem-ch/silkworm/actions/workflows/windows.yml)
[![CodeCov](https://codecov.io/gh/torquem-ch/silkworm/branch/master/graph/badge.svg)](https://codecov.io/gh/torquem-ch/silkworm)
[![GitHub](https://img.shields.io/github/license/torquem-ch/silkworm.svg)](https://github.com/torquem-ch/silkworm/blob/master/LICENSE)
![semver](https://img.shields.io/badge/semver-2.0.0-blue)

## Table of Contents

- [About Silkworm](#about-silkworm)
- [Obtaining Source Code](#obtaining-source-code)
- [Building on Linux & macOS](#building-on-linux--macos)
- [Building on Windows](#building-on-windows)
- [Codemap](#codemap)
- [Testing Silkworm](#testing-silkworm)
- [Style Guide](#style-guide)
- [License](#license)


<a name="about"></a>
## About Silkworm

Silkworm is a greenfield C++ implementation of the Ethereum protocol based on the [Erigon Thorax architecture].
It aims to be the fastest Ethereum client while maintaining the high quality and readability of its source code.
Silkworm uses [libmdbx] as the database engine.

Silkworm was conceived as an evolution of the [Erigon] project,
as outlined in its [release commentary](https://ledgerwatch.github.io/turbo_geth_release.html#Licence-and-language-migration-plan-out-of-scope-for-the-release).

Silkworm is under active development and hasn't reached the alpha phase yet.
Hence, there have been no releases so far.


<a name="source"></a>
## Obtaining Source Code

To obtain Silkworm source code for the first time:
```
git clone --recurse-submodules https://github.com/torquem-ch/silkworm.git
cd silkworm
```

Silkworm uses a few git submodules (some of which have their own submodules).
So after you've updated to the latest code with
```
git pull
```
update the submodules as well by running
```
git submodule update --init --recursive
```


<a name="build_on_unix"></a>
## Building on Linux & macOS

Building Silkworm requires:
* C++20 compiler: [GCC](https://www.gnu.org/software/gcc/) >= 11.2 or [Clang](https://clang.llvm.org/) >= 14
or AppleClang ([Xcode](https://developer.apple.com/xcode/) >= 14.3)
* [CMake](https://cmake.org)
* [Conan](https://conan.io)

Conan requires Python, and can be installed using:

    pip3 install --user conan==1.58.0 chardet

and adding its binary to PATH:

    export "PATH=$HOME/Library/Python/3.9/bin:$PATH"

* Tools for [gmplib](https://gmplib.org/): `sudo apt-get install -y m4 texinfo bison`


Once the prerequisites are installed, bootstrap cmake by running
```
mkdir build
cd build
cmake ..
```
(In the future you don't have to run `cmake ..` again.)

Then run the build itself
```
make -j
```
_Note about parallel builds using `-j`: if not specified the exact number of parallel tasks, the compiler will spawn as many
as the cores available. That may cause OOM errors if the build is executed on a host with a large number of cores but a relatively
small amount of RAM. To work around this, either specify `-jn` where `n` is the number of parallel tasks you want to allow or
remove `-j` completely. Typically, for Silkworm each compiler job requires 4GB of RAM. So, if your total RAM is 16GB, for example,
then `-j4` should be OK, while `-j8` is probably not. It also means that you need a machine with at least 4GB RAM to compile Silkworm._

Now you can run the unit tests. There's one for core and one for node.
```
cmd/test/core_test
cmd/test/node_test
```
or [Ethereum EL Tests]
```
cmd/test/ethereum
```

<a name="build_on_windows"></a>
## Building on Windows

**Note! Windows builds are maintained for compatibility/portability reasons. However, due to the lack of 128-bit integers support by MSVC, execution performance is inferior when compared to Linux builds.**
* Install [Visual Studio] 2019. Community edition is fine.
* Make sure your setup includes CMake support and Windows 10 SDK.
* Install [Conan](https://conan.io) and add it to PATH.
* Open Visual Studio and select File -> CMake...
* Browse the folder where you have cloned this repository and select the file CMakeLists.txt
* Let CMake cache generation complete (it may take several minutes)
* Solution explorer shows the project tree.
* To build simply `CTRL+Shift+B`
* Binaries are written to `%USERPROFILE%\CMakeBuilds\silkworm\build` If you want to change this path simply edit `CMakeSettings.json` file.

**Note ! Memory compression on Windows 10/11**

Windows 10/11 provide a _memory compression_ feature which makes available more RAM than what physically mounted at cost of extra CPU cycles to compress/decompress while accessing data. As MDBX is a memory mapped file this feature may impact overall performances. Is advisable to have memory compression off.

Use the following steps to detect/enable/disable memory compression:
* Open a PowerShell prompt with Admin privileges
* Run `Get-MMAgent` (check whether memory compression is enabled)
* To disable memory compression : `Disable-MMAgent -mc` and reboot
* To enable memory compression : `Enable-MMAgent -mc` and reboot

## Codemap

Apart from the submodules and some auxiliary directories, Silkworm contains the following components:
* [`cmd`](./cmd)
  <br /> The source code of Silkworm executable binaries.
* [`silkworm/core`](./silkworm/core)
  <br /> This module contains the heart of the Ethereum protocol logic as described by the [Yellow Paper].
  Source code within `core` is compatible with WebAssembly and cannot use C++ exceptions.
* [`silkworm/node`](./silkworm/node)
  <br /> This module contains the database, the [staged sync] and other logic necessary to function as an Ethereum node.
  This module depends on the `core` module.
* [`silkworm/sentry`](./silkworm/sentry)
  <br /> This module implements the networking and protocol stacks for `Sentry` component for an Ethereum node based on [Erigon Thorax architecture].
  This module depends on both the `core` and `node` modules.
* [`silkworm/wasm`](./silkworm/wasm)
  <br /> This module allows the `core` the run on WebAssembly. This module depends on both the `core` and `node` modules.

<a name="testing_silkworm"></a>
## Testing Silkworm

**Note: at current state of development Silkworm can't actually sync the chain like Erigon does.**

You can try to run Silkworm to test just the sync on the *pre-Merge* Ethereum chain. In order to do that you need to:

- run an instance of `Erigon Sentry` component from `devel` branch
- set the environment variable `STOP_AT_BLOCK` to a value < 15'537'351 (e.g. STOP_AT_BLOCK=15000000)

### Linux and macOS

#### Erigon Sentry
```
git clone --recurse-submodules https://github.com/ledgerwatch/erigon.git
cd erigon
git checkout devel
make sentry
./build/bin/sentry
```

#### Silkworm
```
export STOP_AT_BLOCK=15000000
./cmd/silkworm
```

### Windows

#### Erigon Sentry
```
git clone --recurse-submodules https://github.com/ledgerwatch/erigon.git
cd erigon
git checkout devel
make sentry
./build/bin/sentry.exe
```

#### Silkworm
```
$env:STOP_AT_BLOCK=15000000
./cmd/silkworm.exe
```

## Use Conan as Package Manager

A custom Conan "profile" can be passed via a cmake argument, for example: 

    cmake .. -DCONAN_PROFILE=macos_arm_clang_13_debug

will use "debug" configuration builds of dependencies.

See available profiles in [cmake/profiles](cmake/profiles).

The conan packages could also be pre-installed using [conan install](https://docs.conan.io/1/reference/commands/consumer/install.html):

    conan install --install-folder=build/conan --build=missing --profile=cmake/profiles/macos_arm_clang_13_debug .


<a name="guide"></a>
## Style Guide

We use the standard C++20 programming language.
We adhere to [Google's C++ Style Guide] with the following differences:

* C++20 rather than C++17.
* `snake_case()` for function names.
* .cpp & .hpp file extensions for C++; .c & .h are reserved for C.
* `using namespace foo` is allowed inside .cpp files, but not inside headers.
* Exceptions are allowed outside the `core` library.
* User-defined literals are allowed.
* Maximum line length is 120, indentation is 4 spaces – see [.clang-format](.clang-format).
* Use `#pragma once` in the headers instead of the classic `#ifndef` guards.


## License

Silkworm is licensed under the terms of the Apache license.
See [LICENSE](LICENSE) for more information.


[CMake]: http://cmake.org
[Ethereum EL Tests]: https://github.com/ethereum/tests
[Erigon]: https://github.com/ledgerwatch/erigon
[Erigon Thorax architecture]: https://github.com/ledgerwatch/erigon#key-features
[GMP]: http://gmplib.org
[Google's C++ Style Guide]: https://google.github.io/styleguide/cppguide.html
[libmdbx]: https://github.com/erthink/libmdbx
[staged sync]: https://github.com/ledgerwatch/erigon/blob/devel/eth/stagedsync/README.md
[Visual Studio]: https://www.visualstudio.com/downloads
[Yellow Paper]: https://ethereum.github.io/yellowpaper/paper.pdf
