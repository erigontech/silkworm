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
  Microsoft.GSL
  VERSION 4.0.0
  URL https://github.com/microsoft/GSL/archive/v4.0.0.tar.gz
  SHA1 909c9540a76fe4b4f71dbbd24126cab3925fb78e
)

hunter_config(
  ethash
  VERSION 0.9.0
  CMAKE_ARGS ETHASH_BUILD_ETHASH=ON ETHASH_BUILD_GLOBAL_CONTEXT=OFF ETHASH_BUILD_TESTS=OFF
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
