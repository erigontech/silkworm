#[[
   Copyright 2022 The Silkworm Authors

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

# cmake-format: off

include(hunter_cmake_args)

hunter_cmake_args(
  abseil
  CMAKE_ARGS
        ABSL_PROPAGATE_CXX_STD=ON
        ABSL_ENABLE_INSTALL=OFF
        ABSL_RUN_TESTS=OFF
)

# Avoid -Werror to overcome GCC 12.1.0 bug breaking Google Benchmark build
# https://github.com/google/benchmark/issues/1398
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105329
hunter_config(
  benchmark
  VERSION 1.6.1
  CMAKE_ARGS BENCHMARK_ENABLE_WERROR=OFF
)

hunter_config(
  Boost
  URL https://boostorg.jfrog.io/artifactory/main/release/1.81.0/source/boost_1_81_0.tar.bz2
  SHA1 898469f1ae407f5cbfca84f63ad602962eebf4cc
)

hunter_config(
  asio-grpc
  URL https://github.com/Tradias/asio-grpc/archive/refs/tags/v2.4.0.tar.gz
  SHA1 85021b69a6ac3e6341813ee67f7142bf63ce5720
  CMAKE_ARGS ASIO_GRPC_USE_BOOST_CONTAINER=ON
)

# Downgrade Protobuf version due to a CMake error in 3.19.4-p0
# (protobuf-module.cmake.in: _protobuf_find_threads)
hunter_config(
  Protobuf
  VERSION 3.14.0-4a09d77-p0
  CMAKE_ARGS
    CMAKE_POLICY_DEFAULT_CMP0063=NEW
    CMAKE_C_VISIBILITY_PRESET=hidden
    CMAKE_CXX_VISIBILITY_PRESET=hidden
    CMAKE_VISIBILITY_INLINES_HIDDEN=ON
)

hunter_config(
  gRPC
  VERSION 1.44.0-p0
  CMAKE_ARGS gRPC_BUILD_TESTS=OFF gRPC_BUILD_CODEGEN=ON gRPC_BUILD_CSHARP_EXT=OFF
)

hunter_config(
  jwt-cpp
  VERSION 0.6.0
  CMAKE_ARGS JWT_DISABLE_PICOJSON=ON JWT_BUILD_EXAMPLES=OFF
)

# cmake-format: on
