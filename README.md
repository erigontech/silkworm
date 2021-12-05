# Silkworm - C++ Ethereum Client

C++ implementation of the Ethereum protocol based on the [Erigon architecture].

[![CircleCI](https://circleci.com/gh/torquem-ch/silkworm.svg?style=svg)](https://circleci.com/gh/torquem-ch/silkworm)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/8npida1piyqw1844/branch/master?svg=true)](https://ci.appveyor.com/project/torquem/silkworm)
[![CodeCov](https://codecov.io/gh/torquem-ch/silkworm/branch/master/graph/badge.svg)](https://codecov.io/gh/torquem-ch/silkworm)

## Table of Contents

- [About Silkworm](#about)
- [Obtaining Source Code](#source)
- [Building on Linux & macOS](#build_on_unix)
- [Building on Windows](#build_on_windows)
- [Codemap](#codemap)
- [Style Guide](#guide)
- [License](#license)


<a name="about"></a>
## About Silkworm

Silkworm is a greenfield C++ implementation of the Ethereum protocol based on the [Erigon architecture].
It aims to be the fastest Ethereum client while maintaining the high quality and readability of its source code.
Silkworm uses [libmdbx] as the database engine.

Silkworm was conceived as an evolution of the [Erigon] project,
as outlined in its [release commentary](https://ledgerwatch.github.io/turbo_geth_release.html#Licence-and-language-migration-plan-out-of-scope-for-the-release).

Silkworm is under active development and hasn't reached the alpha phase yet.
Hence there have been no releases so far.


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
* C++17 compiler (GCC >= 9 or Clang)
* [CMake]
* [GMP] (`sudo apt-get install libgmp3-dev` or `brew install gmp` or https://gmplib.org/manual/Installing-GMP)

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
remove `-j` completely. Typically for Silkworm, each compiler job requires 4GB of RAM. So, if your total RAM is 16GB, for example,
then `-j4` should be OK, while `-j8` is probably not. It also means that you need a machine with at least 4GB RAM to compile Silkworm._

Now you can run the unit tests
```
cmd/core_test
```
or [Ethereum Consensus Tests]
```
cmd/consensus
```

You can also execute Ethereum blocks with Silkworm.
For that, you need an MDBX instance populated with Ethereum blocks,
which can be produced by running [the first 4 stages](https://github.com/ledgerwatch/erigon/tree/master/eth/stagedsync) of [Erigon] sync, which are before the Execute Blocks Stage.
Then run
```
cmd/execute -d <path-to-chaindata>
```

<a name="build_on_windows"></a>
## Building on Windows

**Note! Windows builds are maintained for compatibility/portability reasons. However, due to the lack of 128-bit integers support by MSVC, execution performance is inferior when compared to Linux builds.**
* Install [Visual Studio] 2019. Community edition is fine.
* Make sure your setup includes CMake support and Windows 10 SDK.
* Install [vcpkg](https://github.com/microsoft/vcpkg#quick-start-windows).
* `.\vcpkg\vcpkg install mpir:x64-windows`
* Add <VCPKG_ROOT>\installed\x64-windows\include to your `INCLUDE` environment variable.
* Add <VCPKG_ROOT>\installed\x64-windows\bin to your `PATH` environment variable.
* Install [Perl](https://strawberryperl.com/) (needed for OpenSSL build process)
* Open Visual Studio and select File -> CMake...
* Browse the folder where you have cloned this repository and select the file CMakeLists.txt
* Let CMake cache generation complete (it may take several minutes)
* Solution explorer shows the project tree.
* To build simply `CTRL+Shift+B`
* Binaries are written to `%USERPROFILE%\CMakeBuilds\silkworm\build` If you want to change this path simply edit `CMakeSettings.json` file.


## Codemap

Apart from the submodules and some auxiliary directories, Silkworm contains the following components:
* [`core`](core/)
  <br /> The `core` library contains the bulk of the Ethereum protocol logic as described by the [Yellow Paper].
  Code within `core` is compatible with WebAssembly and may not use C++ exceptions.
* [`node`](node/)
  <br /> The `node` library contains database, [staged sync], and other logic necessary for functioning as an Ethereum node.
  The `node` library depends on the `core` library.
* [`cmd`](cmd/)
  <br /> The source code of  Silkworm executable binaries.


<a name="guide"></a>
## Style Guide

We use the standard C++17 programming language.
We adhere to [Google's C++ Style Guide] with the following differences:

* `snake_case()` for function names.
* .cpp & .hpp file extensions for C++; .c & .h are reserved for C.
* `using namespace foo` is allowed inside .cpp files, but not inside headers.
* Exceptions are allowed outside of the `core` library.
* User-defined literals are allowed.
* Maximum line length is 120, indentation is 4 spaces – see [.clang-format](.clang-format).


## License

Silkworm is licensed under the terms of the Apache license.
See [LICENSE](LICENSE) for more information.


[CMake]: http://cmake.org
[Ethereum Consensus Tests]: https://github.com/ethereum/tests
[Erigon]: https://github.com/ledgerwatch/erigon
[Erigon architecture]: https://github.com/ledgerwatch/erigon#key-features
[GMP]: http://gmplib.org
[Google's C++ Style Guide]: https://google.github.io/styleguide/cppguide.html
[libmdbx]: https://github.com/erthink/libmdbx
[staged sync]: https://github.com/ledgerwatch/erigon/blob/devel/eth/stagedsync/README.md
[Visual Studio]: https://www.visualstudio.com/downloads
[Yellow Paper]: https://ethereum.github.io/yellowpaper/paper.pdf
