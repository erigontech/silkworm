# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(Boost REQUIRED COMPONENTS headers)

# Target 'execute' is used to exercise the Silkworm C API library even if using C++ main
add_executable(execute execute.cpp)

set(PRIVATE_LIBS
    Boost::headers
    silkworm_infra
    silkworm_db
    silkworm_rpcdaemon
    silkworm_capi_static
    silkworm_infra_cli
)

target_link_libraries(execute PRIVATE ${PRIVATE_LIBS})

# Target 'capi_main' is used to check that Silkworm C API header passes pure C compilation (avoid this target in
# sanitizer build due to linking errors w/ libFuzzingEngine dependencies)
if(NOT SILKWORM_SANITIZE)
  add_executable(capi_main main.c)
  target_link_libraries(capi_main PRIVATE silkworm_capi)
endif()
