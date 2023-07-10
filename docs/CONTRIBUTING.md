# Contributing Guide

We use the standard C++20 programming language.
We adhere to [Google's C++ Style Guide] with the following differences:

* C++20 rather than C++17.
* `snake_case()` for function names.
* .cpp & .hpp file extensions for C++; .c & .h are reserved for C.
* `using namespace foo` is allowed inside .cpp files, but not inside headers.
* Exceptions are allowed outside the `core` library.
* User-defined literals are allowed.
* Maximum line length is 120, indentation is 4 spaces. Use `make fmt` to reformat according to the code style.
* Add Apache copyright banners. Use `make lint` to check the proper banner style.
* Use `#pragma once` in the headers instead of the classic `#ifndef` guards.
* [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) runs on CI. The report is attached to the "ARTIFACTS" section of the linux-clang-tidy job that can be found [here](https://app.circleci.com/pipelines/github/torquem-ch/silkworm?branch=master).


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


[Google's C++ Style Guide]: https://google.github.io/styleguide/cppguide.html
