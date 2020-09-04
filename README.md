Silkworm
===

C++ implementation of the Ethereum protocol.
It's conceived as an evolution of the [Turbo-Geth](https://github.com/ledgerwatch/turbo-geth) project,
as outlined in its [release commentary](https://ledgerwatch.github.io/turbo_geth_release.html#Licence-and-language-migration-plan-out-of-scope-for-the-release).

[![CircleCI](https://circleci.com/gh/torquem-ch/silkworm.svg?style=svg)](https://circleci.com/gh/torquem-ch/silkworm)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/8npida1piyqw1844?svg=true)](https://ci.appveyor.com/project/torquem/silkworm)

# Building the source

# Clone the repository

`git clone --recurse-submodules https://github.com/torquem-ch/silkworm.git`

## Linux & macOS
Building silkworm requires:
* C++17 compiler (GCC or Clang)
* [CMake](http://cmake.org)
* [GMP](http://gmplib.org) (`sudo apt-get install libgmp3-dev` or `brew install gmp`)

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
Now you can check database changes (produced by [Turbo-Geth](https://github.com/ledgerwatch/turbo-geth)) with silkworm
```
./check_changes
```
and also run either the unit tests
```
./unit_test
```
or [Ethereum Consensus Tests](https://github.com/ethereum/tests)
```
./consensus
```

## Windows
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
We follow [Google's C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with the following differences:

* `snake_case` for function names.
* .cpp & .hpp file extensions rather than .cc & .h for C++.
* Exceptions are allowed.
* User-defined literals are allowed.
* Max line length is 100.
