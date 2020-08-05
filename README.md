Silkworm
===

C++ implementation of the Ethereum protocol.
It's conceived as an evolution of the [Turbo-Geth](https://github.com/ledgerwatch/turbo-geth) project,
as outlined in its [release commentary](https://ledgerwatch.github.io/turbo_geth_release.html#Licence-and-language-migration-plan-out-of-scope-for-the-release).

# Building the source

Building silkworm requires [cmake](https://cgold.readthedocs.io/en/latest/first-step/installation.html) and a C++17 compiler.
Once the prerequisites are installed, bootstrap cmake build by running
```
mkdir build
cd build
cmake ..
```
(In the future you don't have to run `cmake ..` again.)

Then run the build itself
```
cmake --build . -j
```
Now you can check database changes (produced by [Turbo-Geth](https://github.com/ledgerwatch/turbo-geth)) with silkworm
```
./check_changes
```
or run tests
```
./tests
```

# Code style

We use the standard C++17 programming language, plus C++20 designated initializers.
We follow [Google's C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with the following differences:

* `snake_case` for function names.
* .cpp & .hpp file extensions rather than .cc & .h for C++.
* Exceptions are allowed.
* User-defined literals are allowed.
* Max line length is 100.
