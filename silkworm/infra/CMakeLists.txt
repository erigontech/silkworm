#[[
   Copyright 2023 The Silkworm Authors

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

find_package(absl REQUIRED)
find_package(asio-grpc REQUIRED)
if(CONAN_PACKAGE_MANAGER)
    find_package(Boost REQUIRED container thread)
else()
    find_package(Boost CONFIG REQUIRED container thread)
endif()
find_package(gRPC REQUIRED)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp")
list(FILTER SRC EXCLUDE REGEX "_test\\.cpp$")
list(FILTER SRC EXCLUDE REGEX "_benchmark\\.cpp$")

add_library(silkworm_infra "${SRC}")

# Suppress ASAN/TSAN in gRPC to avoid ODR violation when building Silkworm with sanitizers
# See https://github.com/grpc/grpc/issues/19224
if(SILKWORM_SANITIZE)
    target_compile_definitions(silkworm_infra PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
endif()

target_include_directories(silkworm_infra PUBLIC
  "${SILKWORM_MAIN_DIR}"
  "${SILKWORM_MAIN_DIR}/third_party/magic_enum/include"
)

set(LIBS_PUBLIC
  absl::strings
  asio-grpc::asio-grpc
  Boost::headers
  Boost::thread
  gRPC::grpc++
  silkworm_core
  silkworm_interfaces
)

# cmake-format: off
set(LIBS_PRIVATE
    absl::time
    Boost::container # required for asio-grpc
)
# cmake-format: on
if(MSVC)
    list(APPEND LIBS_PRIVATE ntdll.lib)
endif(MSVC)

target_link_libraries(silkworm_infra PUBLIC "${LIBS_PUBLIC}" PRIVATE "${LIBS_PRIVATE}")
