/*
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
*/

#include "jwt.hpp"

#include <fstream>

#include <catch2/catch.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/test/files.hpp>

namespace silkworm {

static std::string ascii_from_hex(const std::string& hex) {
    const std::optional<Bytes> bytes{from_hex(hex)};
    if (!bytes) {
        throw std::runtime_error{"ascii_from_hex"};
    }
    return {byte_view_to_string_view(*bytes)};
}

TEST_CASE("generate_jwt_token", "[silkworm][rpc][http][jwt]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    test::TemporaryFile tmp_jwt_file;

    SECTION("empty file path") {
        CHECK_THROWS_AS(generate_jwt_token(std::filesystem::path{""}), std::runtime_error);
    }

    SECTION("check generated JWT chars") {
        std::string jwt_token;
        CHECK_NOTHROW((jwt_token = generate_jwt_token(tmp_jwt_file.path())));
        CHECK(jwt_token.size() == 32);
        std::string jwt_token_hex;
        std::ifstream tmp_jwt_ifs{tmp_jwt_file.path()};
        tmp_jwt_ifs >> jwt_token_hex;
        jwt_token_hex = jwt_token_hex.substr(2);
        CHECK(jwt_token == ascii_from_hex(jwt_token_hex));
    }
}

TEST_CASE("load_jwt_token", "[silkworm][rpc][http][jwt]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    test::TemporaryFile tmp_jwt_file;
    std::ofstream tmp_jwt_ofs{tmp_jwt_file.path()};

    SECTION("empty file path") {
        CHECK_THROWS_AS(load_jwt_token(std::filesystem::path{""}), std::runtime_error);
    }

    SECTION("empty file") {
        tmp_jwt_ofs.close();
        CHECK_THROWS_AS(load_jwt_token(tmp_jwt_file.path()), std::runtime_error);
    }

    const std::vector<std::string> kInvalidTokens{
        "",
        "?=?",
        "d4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8",
        "d4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8f",
        "d4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8f4f",
        "d4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8f4ff",
        "0x",
        "0x?=?",
        "0xd4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8",
        "0xd4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8f",
        "0xd4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8f4f",
        "0xd4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8f4ff"};
    for (const auto& token : kInvalidTokens) {
        SECTION("invalid JWT file content: " + token) {
            tmp_jwt_ofs << token;
            tmp_jwt_ofs.close();
            CHECK_THROWS_AS(load_jwt_token(tmp_jwt_file.path()), std::runtime_error);
        }
    }

    const std::vector<std::string> kValidTokens{
        "d4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8f4",
        "0xd4414235d86b6d00ab77bb3eae739605aa9d4036b99bda915ecfb5e170cbf8f4",
    };
    for (const auto& token : kValidTokens) {
        SECTION("valid JWT file content: " + token) {
            tmp_jwt_ofs << token;
            tmp_jwt_ofs.close();
            CHECK_NOTHROW(load_jwt_token(tmp_jwt_file.path()));
        }
    }
}

}  // namespace silkworm
