# Fuzz Tests in Silkworm

SIlkworm uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html) to execute its fuzzy tests. This battle tested library has helped many other projects to uncover bugs. Although the library is currently in the maintenance mode (bug fixing only) it is still sufficient for our needs.
## Execute tests
To build the fuzzer use the following:
```bash
mkdir build
cd build
cmake ../project -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCONAN_PROFILE=linux_x64_clang_16_release -DCMAKE_TOOLCHAIN_FILE=../project/cmake/toolchain/clang_libcxx.cmake -DSILKWORM_FUZZER=ON
cmake --build --target rpcdaemon_fuzzer_test
cmake –-build --target rpcdaemon_fuzzer_diagnostics
```
Then simply run:
```bash
./cmd/test/rpcdaemon_fuzzer_test -detect_leaks=0
```
Note:  we disable leaks detection to ignore known issues with GRPC library.

The command above will start fuzzying without any prior knowledge about the request structure. It can be hours before it forms a valid request. To help the fuzzer, we can provide it with a collection of valid requests which it can use as a starting point, called corpus. Fortunately API test collection has a number of request we can use.

```bash
mkdir -p corpus
for file in ../third_party/execution-apis/tests/*/*.io; do cp --backup=numbered "$file" corpus; done
for file in corpus/*; do sed -i '2,$d' "$file"; done
for file in corpus/*; do sed -i 's/^>> //' "$file"; done
./cmd/test/rpcdaemon_fuzzer_test corpus -max_total_time=86400 -detect_leaks=0
```

## Diagnostics
The fuzzer will stop the execution on a first error. Address, Lean or Undefined sanitizers will try to help us identifying the issue. The fault request is then written to `crash-*` file. 
To help with analysing a single request you can run the diagnostic tool:
```bash
./cmd/test/rpcdaemon_fuzzer_diagnostics '{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x1A","0x2",[95,99]]}'
#or
./cmd/test/rpcdaemon_fuzzer_diagnostics -f crash-file
```

## Trophies
1.	Various validation errors which led to the introduction of `rpc::json_rpc::Validator`
2.	BlockNum accepting ill-formatted numbers, e.g. `5x5`
3.	`{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x1A","0x2",[95,99]]}` - triggers ASAN error

## Future development

Recently some progress has been made on [using AI](https://security.googleblog.com/2024/01/scaling-security-with-ai-from-detection.html) in fuzzy tests. This is a very promising technology which could be adapted in our case:
1. Switch fuzzer library to [OSS-Fuzz](https://github.com/google/oss-fuzz) in libFuzzer mode
2. Use [oss-fuzz-gen](https://github.com/google/oss-fuzz-gen) for target generation
