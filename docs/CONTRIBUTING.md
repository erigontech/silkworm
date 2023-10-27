# Contributing Guide

We use the [ISO Standard C++][cpp-standard-iso] programming language, specifically C++20.
If you contribute to this project, your contributions will be made under [our license][silkworm-license].

## C++ Core Guidelines

We follow the [C++ Core Guidelines][cpp-core-guidelines] as much as possible.


## Style Guide

We adhere to [Google's C++ Style Guide][cpp-google-style-guide] with the following differences:

* `snake_case()` for function names.
* .cpp & .hpp file extensions for C++; .c & .h are reserved for C.
* `using namespace foo` is allowed inside .cpp files, but not inside headers.
* Exceptions are allowed outside the `core` library.
* User-defined literals are allowed.
* Maximum line length is 120, indentation is 4 spaces. Use `make fmt` to reformat according to the code style.
* Add Apache copyright banners. Use `make lint` to check the proper banner style.
* Use `#pragma once` in the headers instead of the classic `#ifndef` guards.
* `template <Concept T>` syntax is allowed.

In addition to the [Boost libraries permitted in the style guide](https://google.github.io/styleguide/cppguide.html#Boost), we allow:
* Algorithm
* Asio
* Circular Buffer
* DLL
* Process
* Signals2
* System
* Thread

[clang-tidy](https://clang.llvm.org/extra/clang-tidy/) runs on CI. The report is attached to the "ARTIFACTS" section of the linux-clang-tidy job that can be found [here](https://app.circleci.com/pipelines/github/torquem-ch/silkworm?branch=master).


## Code Structure

Apart from the submodules and some auxiliary directories, Silkworm contains the following components:
* [`cmd`](./cmd)
  <br /> The source code of Silkworm executable binaries.
* [`silkworm/core`](./silkworm/core)
  <br /> This module contains the heart of the Ethereum protocol logic as described by the [Yellow Paper][ethereum-yellow-paper].
  Source code within `core` is compatible with WebAssembly and cannot use C++ exceptions.
* [`silkworm/infra`](./silkworm/infra)
  <br /> This module contains common abstractions and facilities useful for networking, concurrency and system programming.
  This module depends on the `core` and `interfaces` modules.
* [`silkworm/interfaces`](./silkworm/interfaces)
  <br /> This module contains the definition of our internal [gRPC][grpc] interfaces based on [Erigon architecture][erigon-interfaces] and their generated stubs and skeletons.
* [`silkworm/node`](./silkworm/node)
  <br /> This module contains the database, the [staged sync] and other logic necessary to function as an Ethereum node.
  This module depends on the `core` module.
* [`silkworm/sentry`](./silkworm/sentry)
  <br /> This module implements the networking and protocol stacks for the `Sentry` component for an Ethereum node based on [Erigon architecture][erigon-interfaces].
  This module depends on the `core`, `infra` and `node` modules.
* [`silkworm/rpc`](./silkworm/silkrpc)
  <br /> This module implements the networking and protocol stacks for the `RpcDaemon` component for an Ethereum node based on [Erigon architecture][erigon-interfaces],
  exposing the vast majority of the [Ethereum JSON RPC Execution API][ethereum-execution-api]. This module depends on the `core`, `infra` and `node` modules.
* [`silkworm/sync`](./silkworm/sync)
  <br /> This module implements the networking and protocol stacks for the `Consensus` component for an Ethereum node based on [Erigon architecture][erigon-interfaces],
  exposing the portion of the [Ethereum JSON RPC Execution API][ethereum-execution-api] necessary to interact with any Consensus Layer client.
  This module depends on the `core`, `infra`, `node` and `rpc` modules.
* [`silkworm/wasm`](./silkworm/wasm)
  <br /> This module allows the `core` the run on WebAssembly. This module depends on both the `core` and `node` modules.


[silkworm-license]: https://github.com/torquem-ch/silkworm/tree/master/LICENSE
[cpp-standard-iso]: https://isocpp.org
[cpp-core-guidelines]: https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines
[cpp-google-style-guide]: https://google.github.io/styleguide/cppguide.html
[ethereum-yellow-paper]: https://ethereum.github.io/yellowpaper/paper.pdf
[grpc]: https://grpc.io
[erigon-interfaces]: https://github.com/ledgerwatch/interfaces
[ethereum-execution-api]: https://github.com/ethereum/execution-apis
