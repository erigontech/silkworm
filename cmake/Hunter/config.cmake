#[[
   Copyright 2020-2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
]]

hunter_config(
  Catch
  VERSION 2.13.7
  URL https://github.com/catchorg/Catch2/archive/v2.13.7.tar.gz
  SHA1 fa8f14ccf852413d3c6d3999145ada934d37d773
)

hunter_config(
  Microsoft.GSL
  VERSION 3.1.0
  URL https://github.com/microsoft/GSL/archive/v3.1.0.tar.gz
  SHA1 3f2891a46595806563e7a0e25bb7ecbb30776445
)

hunter_config(
  ethash
  VERSION 0.9.0
  CMAKE_ARGS ETHASH_BUILD_ETHASH=ON ETHASH_BUILD_GLOBAL_CONTEXT=NO ETHASH_BUILD_TESTS=OFF
)

hunter_config(
  re2
  VERSION 2021.11.01
  URL https://github.com/google/re2/archive/2021-11-01.tar.gz
  SHA1 4c18662f103ef53f106f8f98d7b46b723615e14f
)

# Downgrade Protobuf version due to a CMake error in 3.19.4-p0
# (protobuf-module.cmake.in: _protobuf_find_threads)
hunter_config(
  Protobuf
  VERSION 3.14.0-4a09d77-p0
)

hunter_config(
  gRPC
  VERSION 1.44.0-p0
  CMAKE_ARGS gRPC_BUILD_TESTS=OFF gRPC_BUILD_CODEGEN=ON gRPC_BUILD_CSHARP_EXT=OFF
)

hunter_config(
  CLI11
  VERSION 2.2.0
  URL https://github.com/CLIUtils/CLI11/archive/v2.2.0.tar.gz
  SHA1 8ff2b5ef3436d73ce7f9db0bd94a912e305f0967
)
