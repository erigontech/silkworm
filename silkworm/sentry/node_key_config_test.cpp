// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node_key_config.hpp"

#include <fstream>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <gsl/util>

#include <silkworm/infra/common/directories.hpp>

namespace silkworm::sentry {

using namespace std;
namespace fs = filesystem;

static fs::path temp_path() {
    return TemporaryDirectory::get_unique_temporary_path();
}

TEST_CASE("NodeKeyConfig::load") {
    SECTION("ok") {
        std::string_view expected_key_hex{"ef0fdb513d775f161062e9cfd68ce4f0dfb3f2fe72d4947a7ce4444e49dc8216"};
        auto file_path = temp_path();
        [[maybe_unused]] auto _ = gsl::finally([&file_path] { fs::remove(file_path); });

        ofstream file{file_path};
        file << expected_key_hex;
        file.close();

        // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
        REQUIRE((NodeKeyConfig(file_path).load().private_key_hex() == expected_key_hex));
    }

    SECTION("not exists") {
        CHECK_THROWS(NodeKeyConfig(temp_path()).load());
    }

    SECTION("empty file") {
        auto file_path = temp_path();
        [[maybe_unused]] auto _ = gsl::finally([&file_path] { fs::remove(file_path); });

        ofstream file{file_path};
        file.close();

        CHECK_THROWS(NodeKeyConfig(file_path).load());
    }

    SECTION("invalid file") {
        auto file_path = temp_path();
        [[maybe_unused]] auto _ = gsl::finally([&file_path] { fs::remove(file_path); });

        ofstream file{file_path};
        file << "hello";
        file.close();

        CHECK_THROWS(NodeKeyConfig(file_path).load());
    }
}

}  // namespace silkworm::sentry
