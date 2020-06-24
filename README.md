Silkworm
===

C++ implementation of the Ethereum protocol.

# Building the source

Building silkworm requires [cmake](https://cgold.readthedocs.io/en/latest/first-step/installation.html) and a C++17 compiler.
Once the prerequisites are installed, bootstrap cmake build by running
```
cmake -H. -B_build
```
(In the future you don't have to run `cmake -H. -B_build` again.)

Then run the build itself
```
cmake --build _build -- -j
```
Now you can run silkworm
```
_build/silkworm
```
or its tests
```
_build/tests/tests
```

# Code style

We use the standard C++17 programming language, plus C++20 designated initializers.
We follow [Google's C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with the following exceptions:

* .cpp & .hpp file extensions rather than .cc & .h for C++.
* Exceptions are allowed.
* User-defined literals are allowed.
* Max line length is 100.
