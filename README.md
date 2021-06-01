Silkworm
===

C++ implementation of the Ethereum protocol.
It's conceived as an evolution of the [Erigon] project,
as outlined in its [release commentary](https://ledgerwatch.github.io/turbo_geth_release.html#Licence-and-language-migration-plan-out-of-scope-for-the-release).

[![CircleCI](https://circleci.com/gh/torquem-ch/silkworm.svg?style=svg)](https://circleci.com/gh/torquem-ch/silkworm)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/8npida1piyqw1844/branch/master?svg=true)](https://ci.appveyor.com/project/torquem/silkworm)
[![CodeCov](https://codecov.io/gh/torquem-ch/silkworm/branch/master/graph/badge.svg)](https://codecov.io/gh/torquem-ch/silkworm)

# Building the source

# Clone the repository

```
git clone --recurse-submodules https://github.com/torquem-ch/silkworm.git
```

To update the submodules later on run
```
git submodule update --init --recursive
```

## Linux & macOS
Building silkworm requires:
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

Now you can run the unit tests
```
cmd/core_test
```
or [Ethereum Consensus Tests]
```
cmd/consensus
```

You can also execute Ethereum blocks with Silkworm.
For that you need an LMDB instance populated with Ethereum blocks,
which can be produced by running [the first 4 stages](https://github.com/ledgerwatch/erigon/tree/master/eth/stagedsync) of [Erigon] sync, which are before the Execute Blocks Stage.
Then run
```
cmd/execute -d <path-to-chaindata>
```


## Windows
**Note ! Windows builds are maintained for compatibility/portability reasons. However, due to the lack of 128 bit integers support by MSVC, execution performance is inferior when compared to Linux builds.**
* Install [Visual Studio](https://www.visualstudio.com/downloads) 2019. Community edition is fine.
* Make sure your setup includes CMake support and Windows 10 SDK.
* Install [vcpkg](https://github.com/microsoft/vcpkg#quick-start-windows).
* `.\vcpkg\vcpkg install mpir:x64-windows`
* Add <VCPKG_ROOT>\installed\x64-windows\include to your `INCLUDE` environment variable.
* Add <VCPKG_ROOT>\installed\x64-windows\bin to your `PATH` environment variable.
* Open Visual Studio and select File -> CMake...
* Browse the folder where you have cloned this repository and select the file CMakeLists.txt
* Let CMake cache generation complete (it may take several minutes)
* Solution explorer shows the project tree.
* To build simply `CTRL+Shift+B`
* Binaries are written to `%USERPROFILE%\CMakeBuilds\silkworm\build` If you want to change this path simply edit `CMakeSettings.json` file.

# Code style

We use the standard C++17 programming language.
We follow [Google's C++ Style Guide] with the following differences:

* `snake_case` for function names.
* .cpp & .hpp file extensions for C++; .c & .h are reserved for C.
* `using namespace foo` is allowed inside .cpp files, but not inside headers.
* Exceptions are allowed outside of Silkworm Core.
* User-defined literals are allowed.
* Maximum line length is 120, indentation is 4 spaces – see `.clang-format`.

[CMake]: http://cmake.org
[Ethereum Consensus Tests]: https://github.com/ethereum/tests
[Erigon]: https://github.com/ledgerwatch/erigon
[GMP]: http://gmplib.org
[Google's C++ Style Guide]: https://google.github.io/styleguide/cppguide.html
