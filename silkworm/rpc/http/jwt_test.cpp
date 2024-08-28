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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/hex.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/infra/test_util/temporary_file.hpp>

namespace silkworm {

TEST_CASE("generate_jwt_token", "[silkworm][rpc][http][jwt]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    test_util::TemporaryFile tmp_jwt_file;

    SECTION("empty file path") {
        CHECK_THROWS_AS(generate_jwt_token(std::filesystem::path{""}), std::runtime_error);
    }

    static constexpr size_t kExpectedJwtTokenChars{32};
    static constexpr size_t kExpectedJwtTokenHexSize{32 * 2 + 2};  // +2 for 0x

    SECTION("check generated JWT chars") {
        REQUIRE(std::filesystem::exists(tmp_jwt_file.path()));
        std::string jwt_token;
        CHECK_NOTHROW((jwt_token = generate_jwt_token(tmp_jwt_file.path())));
        REQUIRE(std::filesystem::file_size(tmp_jwt_file.path()) == kExpectedJwtTokenHexSize);
        CHECK(jwt_token.size() == kExpectedJwtTokenChars);
        std::string jwt_token_hex;
        std::ifstream tmp_jwt_ifs{tmp_jwt_file.path()};
        tmp_jwt_ifs >> jwt_token_hex;
        REQUIRE(jwt_token_hex.size() == kExpectedJwtTokenHexSize);
        jwt_token_hex = jwt_token_hex.substr(2);
        CHECK(jwt_token == test_util::ascii_from_hex(jwt_token_hex));
    }

    SECTION("file path does not exist") {
        const auto jwt_parent_path = TemporaryDirectory::get_unique_temporary_path();
        REQUIRE(!std::filesystem::exists(jwt_parent_path));
        const auto jwt_file_path = jwt_parent_path / "jwt.hex";
        REQUIRE(!std::filesystem::exists(jwt_file_path));
        std::string jwt_token;
        CHECK_NOTHROW((jwt_token = generate_jwt_token(jwt_file_path)));
        REQUIRE(std::filesystem::exists(jwt_file_path));
        REQUIRE(std::filesystem::file_size(jwt_file_path) == kExpectedJwtTokenHexSize);
        CHECK(jwt_token.size() == kExpectedJwtTokenChars);
        std::string jwt_token_hex;
        std::ifstream tmp_jwt_ifs{jwt_file_path};
        tmp_jwt_ifs >> jwt_token_hex;
        REQUIRE(jwt_token_hex.size() == kExpectedJwtTokenHexSize);
        jwt_token_hex = jwt_token_hex.substr(2);
        CHECK(jwt_token == test_util::ascii_from_hex(jwt_token_hex));
    }
}

TEST_CASE("load_jwt_token", "[silkworm][rpc][http][jwt]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    test_util::TemporaryFile tmp_jwt_file;
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
