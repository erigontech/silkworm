/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "silkworm.h"

#include <iostream>

#include <catch2/catch.hpp>

#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/db/mdbx.hpp>

namespace silkworm {

#define SILKWORM_CAPI_TEST_DATA_DIR_PATH "/tmp"

struct CApiTest {
  private:
    // TODO(canepat) remove test_util::StreamSwap objects when C API settings include log level
    std::stringstream string_cout, string_cerr;
    test_util::StreamSwap cout_swap{std::cout, string_cout};
    test_util::StreamSwap cerr_swap{std::cerr, string_cerr};

    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
};

template <size_t N = 32>
static void c_string_copy(char dst[N], const char* src) {
    std::strncpy(dst, src, N - 1);
    dst[N - 1] = '\0';
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_libmdbx_version: OK", "[silkworm][capi]") {
    CHECK(std::strcmp(silkworm_libmdbx_version(), ::mdbx::get_version().git.describe) == 0);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty settings", "[silkworm][capi]") {
    SilkwormSettings settings{};
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INVALID_PATH);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty data folder path", "[silkworm][capi]") {
    SilkwormSettings settings{
        .data_dir_path = "",
    };
    c_string_copy(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INVALID_PATH);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty MDBX version", "[silkworm][capi]") {
    SilkwormSettings settings{
        .data_dir_path = SILKWORM_CAPI_TEST_DATA_DIR_PATH,
        .libmdbx_version = "",
    };
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INCOMPATIBLE_LIBMDBX);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: incompatible MDBX version", "[silkworm][capi]") {
    SilkwormSettings settings{
        .data_dir_path = SILKWORM_CAPI_TEST_DATA_DIR_PATH,
        .libmdbx_version = "v0.1.0",
    };
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INCOMPATIBLE_LIBMDBX);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: OK", "[silkworm][capi]") {
    SilkwormSettings settings{
        .data_dir_path = SILKWORM_CAPI_TEST_DATA_DIR_PATH,
    };
    c_string_copy(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_OK);
    CHECK(handle);
    CHECK(silkworm_fini(handle) == SILKWORM_OK);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_fini: not initialized", "[silkworm][capi]") {
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_fini(handle) == SILKWORM_INVALID_HANDLE);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_fini: OK", "[silkworm][capi]") {
    SilkwormSettings settings{
        .data_dir_path = SILKWORM_CAPI_TEST_DATA_DIR_PATH,
    };
    c_string_copy(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    REQUIRE(silkworm_init(&handle, &settings) == SILKWORM_OK);
    CHECK(silkworm_fini(handle) == SILKWORM_OK);
}

}  // namespace silkworm
