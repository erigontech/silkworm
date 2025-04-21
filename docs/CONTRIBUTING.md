# Contributing Guide

We use the [ISO Standard C++][cpp-standard-iso] programming language, specifically C++20.
If you contribute to this project, your contributions will be made under [our license][silkworm-license].

The contributions must follow [Silkworm code style](code_style.md).
Use `make fmt lint` to format the code and perform basic checks locally before submitting a PR.

## Code Structure

Apart from the submodules and some auxiliary directories, Silkworm contains the following components:
* [`cmd`][silkworm-cmd]
  <br /> The source code of Silkworm executable binaries.
* [`silkworm/capi`][silkworm-capi]
  <br /> This module contains the C API exposed by Silkworm for inclusion into [Erigon][erigon] Golang Cgo.
  This module depends on the `core`, `infra`, `node`, `rpc` and `sentry` modules.
* [`silkworm/core`][silkworm-core]
  <br /> This module contains the heart of the Ethereum protocol logic as described by the [Yellow Paper][ethereum-yellow-paper].
  Source code within `core` is compatible with WebAssembly and cannot use C++ exceptions.
* [`silkworm/infra`][silkworm-infra]
  <br /> This module contains common abstractions and facilities useful for networking, concurrency and system programming.
  This module depends on the `core` and `interfaces` modules.
* [`silkworm/interfaces`][silkworm-interfaces]
  <br /> This module contains the definition of our internal [gRPC][grpc] interfaces based on [Erigon architecture][erigon-interfaces] and their generated stubs and skeletons.
* [`silkworm/node`][silkworm-node]
  <br /> This module contains the database, the staged sync and other logic necessary to function as an Ethereum node.
  This module depends on the `core` module.
* [`silkworm/rpc`][silkworm-rpc]
  <br /> This module implements the networking and protocol stacks for the `RpcDaemon` component for an Ethereum node based on [Erigon architecture][erigon-interfaces],
  exposing the vast majority of the [Ethereum JSON RPC Execution API][ethereum-execution-api]. This module depends on the `core`, `infra` and `node` modules.
* [`silkworm/sentry`][silkworm-sentry]
  <br /> This module implements the networking and protocol stacks for the `Sentry` component for an Ethereum node based on [Erigon architecture][erigon-interfaces].
  This module depends on the `core`, `infra` and `node` modules.
* [`silkworm/sync`][silkworm-sync]
  <br /> This module implements the networking and protocol stacks for the `Consensus` component for an Ethereum node based on [Erigon architecture][erigon-interfaces],
  exposing the portion of the [Ethereum JSON RPC Execution API][ethereum-execution-api] necessary to interact with any Consensus Layer client.
  This module depends on the `core`, `infra`, `node` and `rpc` modules.
* [`silkworm/wasm`][silkworm-wasm]
  <br /> This module allows the `core` the run on WebAssembly. This module depends on both the `core` and `node` modules.


## Dependency Management

Silkworm uses [Conan 1.x][conan] as package manager, but also relies on Git submodules for some libraries.

### Conan

If you need to add/remove/update any library managed in Conan, just edit the Silkworm [Conan recipe][silkworm-conan].

### Submodules

Silkworm uses also some 3rd-party libraries kept as Git submodules in [third-party][silkworm-third_party] folder.

#### Add

If you need to add library `lib` to Silkworm submodules, the following procedure must be applied:

1. mkdir third_party/<lib>
2. git submodule add <github_repo_http_url> third_party/<lib>/<lib>
3. add third_party/<lib>/CMakeLists.txt with library-specific build instructions (e.g. build options)
4. update third_party/CMakeLists.txt

#### Remove

If you need to permanently remove library `lib` from Silkworm submodules, the following procedure must be applied:

1. git submodule deinit -f third_party/<lib>/<lib>
2. git rm -rf third_party/<lib>
3. update third_party/CMakeLists.txt
4. rm -rf .git/modules/third_party/<lib>

#### Update

If you need to update library `lib` in Silkworm submodules to `commit_hash`, the following procedure must be applied:

1. cd third_party/<lib>/<lib>
2. git checkout <commit_hash>


## Updating Internal gRPC Interfaces

If you need to update gRPC protocol definitions (i.e. `.proto` files) and related stubs/skeletons for internal
[Erigon interfaces][erigon-interfaces], the following procedure must be applied:

1. determine the current version used in Erigon as `commit_hash` from [here][erigon-interfaces-version]
2. cd third_party/erigon-interfaces
3. git pull
4. git checkout <commit_hash>


## Updating Snapshots

If you need to update the list of builtin snapshots in Silkworm, the following procedure must be applied:

* update `erigon-snapshot` submodule to the new commit
* generate the embedded C++ code bindings for predefined snapshots by executing from project home folder:
```
<build_folder>/silkworm/dev/cli/embed_toml -i third_party/erigon-snapshot -o silkworm/db/datastore/snapshots/config/chains
```


## Adding Network Genesis Definitions

We use configuration files in JSON format to specify the formal genesis definition for any supported networks. You can find
all the currently supported configurations looking at `genesis_<network>.json` files in `silkworm/core/chain` folder.

If you need to expand or modify the network configurations used by Silkworm, the following procedure must be applied:

1. add new or edit existing JSON genesis files in `silkworm/core/chain` following the naming convention `genesis_<network>.json`
2. generate the C++ code bindings for JSON genesis files by executing from project home folder:
```
<build_folder>/silkworm/dev/cli/embed_json -i silkworm/core/chain -o silkworm/core/chain -w
```


## Updating Ethereum JSON-RPC Specification

We use the specification in [Ethereum JSON RPC Execution API][ethereum-execution-api] in order to formally validate the
incoming requests in our RPC daemon.

### Update Specification from Official Source
If you need to update the official specification imported by Silkworm, the following procedure must be applied:

1. update `execution-apis` submodule to the new commit
2. generate the all-in-one JSON specification file following the build instructions in [Ethereum JSON RPC Execution API][ethereum-execution-api]
3. copy and rename the generated JSON specification file into `silkworm/rpc/json_rpc/specification.json`, resolving the conflicts that may arise 
4. generate the C++ code bindings for JSON specification by executing from project home folder:
```
<build_folder>/silkworm/dev/cli/embed_json -i silkworm/rpc/json_rpc -o silkworm/rpc/json_rpc -p specification -n silkworm::rpc::json_rpc -w
```

### Patch Local Specification
If you need to patch the local copy of the specification used by Silkworm, the following procedure must be applied:

1. edit the generated JSON specification file in `silkworm/rpc/json_rpc/specification.json`
2. generate the C++ code bindings for JSON specification as specified at step 4. in previous section above


## C API for Erigon

One of the main goals of Silkworm is providing fast C++ libraries directly usable within [Erigon][erigon]. In order to
achieve this goal, Silkworm defines its [C API][silkworm-capi-header] and provides *silkworm_capi* library built by a
dedicated build target. Such library is then integrated within Erigon using the Golang Cgo facility by means of the
[Silkworm Go bindings][silkworm-go].

### Development and Testing

Developing and testing Silkworm as a library within Erigon requires the following steps:

1. clone **silkworm**, **silkworm-go** and **erigon** repositories into the same parent directory
2. build *silkworm_capi* target into silkworm/build
3. cd erigon && ./turbo/silkworm/silkworm_go_devenv.sh $PWD/../silkworm $PWD/../silkworm/build $PWD/../silkworm-go
4. Edit silkworm, silkworm-go and erigon sources, rebuild and run them as usual

The linkage between silkworm and erigon happens through the silkworm-go repository (see `cat go.work` in the parent
directory).
If you are sure in advance that no change to silkworm-go will be necessary (i.e. you are going to change neither the C
API declarations nor the Go bindings), then you can omit the last argument to the silkworm_go_devenv.sh script: in such
case, silkworm-go checkout is automatically put in a temporary directory.


### Cutting C-API Release (maintainers only)

Updating the version of Silkworm included in Erigon requires the following steps:

1. cut a new release of silkworm_capi library in silkworm by issuing a new tag named ``capi-<x.y.z>``
2. go to Actions -> Release -> Run workflow for a new version of silkworm-go to be built and tagged as ``v<x.y.z>``
3. wait about 20 min for this CI job to finish: https://app.circleci.com/pipelines/github/erigontech/silkworm-go
4. update your existing PR or open a new one on erigon to upgrade the silkworm-go module by running the command
   `go get github.com/erigontech/silkworm-go@v<x.y.z>`[^1] and then `go mod tidy`


[silkworm-license]: https://github.com/erigontech/silkworm/tree/master/LICENSE
[silkworm-cmd]: https://github.com/erigontech/silkworm/tree/master/cmd
[silkworm-capi]: https://github.com/erigontech/silkworm/tree/master/silkworm/capi
[silkworm-core]: https://github.com/erigontech/silkworm/tree/master/silkworm/core
[silkworm-infra]: https://github.com/erigontech/silkworm/tree/master/silkworm/infra
[silkworm-interfaces]: https://github.com/erigontech/silkworm/tree/master/silkworm/interfaces
[silkworm-node]: https://github.com/erigontech/silkworm/tree/master/silkworm/node
[silkworm-sentry]: https://github.com/erigontech/silkworm/tree/master/silkworm/sentry
[silkworm-rpc]: https://github.com/erigontech/silkworm/tree/master/silkworm/rpc
[silkworm-sync]: https://github.com/erigontech/silkworm/tree/master/silkworm/sync
[silkworm-wasm]: https://github.com/erigontech/silkworm/tree/master/silkworm/wasm
[silkworm-conan]: https://github.com/erigontech/silkworm/tree/master/conanfile.py
[silkworm-third_party]: https://github.com/erigontech/silkworm/tree/master/third_party
[silkworm-capi-header]: https://github.com/erigontech/silkworm/tree/master/silkworm/capi/silkworm.h
[silkworm-go]: https://github.com/erigontech/silkworm-go
[cpp-standard-iso]: https://isocpp.org
[ethereum-yellow-paper]: https://ethereum.github.io/yellowpaper/paper.pdf
[conan]: https://conan.io
[grpc]: https://grpc.io
[erigon]: https://github.com/erigontech/erigon
[erigon-interfaces]: https://github.com/erigontech/interfaces
[erigon-interfaces-version]: https://github.com/erigontech/erigon/blob/main/erigon-lib/go.mod
[ethereum-execution-api]: https://github.com/ethereum/execution-apis

[^1]: You may need to use `GOPRIVATE=github.com/erigontech/silkworm-go go get github.com/erigontech/silkworm-go@v<x.y.z>`
to avoid any early failure until the tag is publicly available.
