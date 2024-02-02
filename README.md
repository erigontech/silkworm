# Silkworm - C++ Ethereum Execution Client

C++ implementation of the Ethereum Execution Layer (EL) protocol based on the [Erigon Thorax architecture].

[![Linux](https://circleci.com/gh/erigontech/silkworm.svg?style=shield)](https://circleci.com/gh/erigontech/silkworm)
[![macOS](https://github.com/erigontech/silkworm/actions/workflows/macOS.yml/badge.svg)](https://github.com/erigontech/silkworm/actions/workflows/macOS.yml)
[![Windows](https://github.com/erigontech/silkworm/actions/workflows/windows.yml/badge.svg)](https://github.com/erigontech/silkworm/actions/workflows/windows.yml)
[![codecov](https://codecov.io/gh/erigontech/silkworm/graph/badge.svg?token=89IPVJGR4Q)](https://codecov.io/gh/erigontech/silkworm)

## Table of Contents

- [About Silkworm](#about)
- [Obtaining Source Code](#source-code)
- [Building on Linux & macOS](#build-on-unix)
- [Building on Windows](#build-on-windows)
- [Testing Silkworm](#testing)
- [Contributing](#contributing)
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


<a name="source-code"></a>
## Obtaining Source Code

To obtain Silkworm source code for the first time:
```
git clone --recurse-submodules https://github.com/erigontech/silkworm.git
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


<a name="build-on-unix"></a>
## Building on Linux & macOS

Building Silkworm requires:
* C++20 compiler: [GCC](https://www.gnu.org/software/gcc/) >= 11.2 or [Clang](https://clang.llvm.org/) >= 15
or AppleClang ([Xcode](https://developer.apple.com/xcode/) >= 14.3)
* [CMake](https://cmake.org)
* [Conan](https://conan.io)

Conan requires Python, and can be installed using:

    pip3 install --user conan==1.60.2 chardet

and adding its binary to PATH:

    export "PATH=$HOME/Library/Python/3.9/bin:$PATH"


Once the prerequisites are installed, bootstrap cmake by running
```
mkdir build
cd build
cmake ..
```
(In the future you don't have to run `cmake ..` again.)


A custom Conan "profile" can be passed via a cmake argument, for example: 

    cmake .. -DCONAN_PROFILE=macos_arm64_clang_13_debug

will use "debug" configuration builds of dependencies.

See available profiles in [cmake/profiles](cmake/profiles).

The conan packages could also be pre-installed using [conan install](https://docs.conan.io/1/reference/commands/consumer/install.html):

    conan install --install-folder=build/conan --build=missing --profile=cmake/profiles/macos_arm64_clang_13_debug .


Then run the build itself
```
make -j
```
_Note about parallel builds using `-j`: if not specified the exact number of parallel tasks, the compiler will spawn as many
as the cores available. That may cause OOM errors if the build is executed on a host with a large number of cores but a relatively
small amount of RAM. To work around this, either specify `-jn` where `n` is the number of parallel tasks you want to allow or
remove `-j` completely. Typically, for Silkworm each compiler job requires 4GB of RAM. So, if your total RAM is 16GB, for example,
then `-j4` should be OK, while `-j8` is probably not. It also means that you need a machine with at least 4GB RAM to compile Silkworm._

Now you can run the unit tests
```
make test
```
or the [Ethereum EL Tests]
```
cmd/test/ethereum
```


<a name="build-on-windows"></a>
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


<a name="testing"></a>
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


<a name="contributing"></a>
## Contributing

If you want to contribute, you can read our [contribution guidelines](docs/CONTRIBUTING.md).


<a name="license"></a>
## License

Silkworm is licensed under the terms of the Apache license.
See [LICENSE](LICENSE) for more information.


[Ethereum EL Tests]: https://github.com/ethereum/tests
[Erigon]: https://github.com/ledgerwatch/erigon
[Erigon Thorax architecture]: https://github.com/ledgerwatch/interfaces/blob/master/_docs/README.md
[GMP]: http://gmplib.org
[libmdbx]: https://github.com/erthink/libmdbx
[staged sync]: https://github.com/ledgerwatch/erigon/blob/devel/eth/stagedsync/README.md
[Visual Studio]: https://www.visualstudio.com/downloads
[Yellow Paper]: https://ethereum.github.io/yellowpaper/paper.pdf
