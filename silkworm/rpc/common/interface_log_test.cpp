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

#include "interface_log.hpp"

#include <fstream>
#include <memory>
#include <string>

#include <absl/strings/match.h>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

namespace silkworm::rpc {

TEST_CASE("InterfaceLog dump: full (req+rsp)", "[rpc][common][interface_log]") {
    const auto tmp_dir{TemporaryDirectory::get_unique_temporary_path()};
    InterfaceLogSettings settings{
        .enabled = true,
        .ifc_name = "eth_rpc",
        .container_folder = tmp_dir,
        .dump_response = true,
    };
    auto ifc_log{std::make_unique<InterfaceLog>(settings)};
    REQUIRE(!ifc_log->path().empty());
    ifc_log->log_req(R"({"json":"2.0"})");
    ifc_log->log_rsp(R"({"json":"2.0"})");
    std::ifstream log_ifstream{ifc_log->path().string()};

    // Log file must be empty before flushing
    CHECK(log_ifstream.get() == -1);
    CHECK(log_ifstream.eof());
    log_ifstream.clear();
    log_ifstream.seekg(0);

    SECTION("explicit flush") {
        // InterfaceLog instance gets flushed here but remains alive until the end
        ifc_log->flush();
    }

    SECTION("implicit flush") {
        // InterfaceLog instance gets destroyed here and implicitly flushed
        ifc_log.reset();
    }

    // First line must be the request
    std::string content;
    std::getline(log_ifstream, content);
    CHECK(absl::StrContains(content, R"(REQ -> {"json":"2.0"})"));
    // Second line must be the response
    std::getline(log_ifstream, content);
    CHECK(absl::StrContains(content, R"(RSP <- {"json":"2.0"})"));
    // No other content is present
    CHECK(log_ifstream.get() == -1);
    CHECK(log_ifstream.eof());
}

TEST_CASE("InterfaceLog dump: default (only req)", "[rpc][common][interface_log]") {
    const auto tmp_dir{TemporaryDirectory::get_unique_temporary_path()};
    InterfaceLogSettings settings{
        .enabled = true,
        .ifc_name = "eth_rpc",
        .container_folder = tmp_dir,
    };
    auto ifc_log{std::make_unique<InterfaceLog>(settings)};
    REQUIRE(!ifc_log->path().empty());
    ifc_log->log_req(R"({"json":"2.0"})");
    ifc_log->log_rsp(R"({"json":"2.0"})");
    std::ifstream log_ifstream{ifc_log->path().string()};

    // Log file must be empty before flushing
    CHECK(log_ifstream.get() == -1);
    CHECK(log_ifstream.eof());
    log_ifstream.clear();
    log_ifstream.seekg(0);

    SECTION("explicit flush") {
        // InterfaceLog instance gets flushed here but remains alive until the end
        ifc_log->flush();
    }

    SECTION("implicit flush") {
        // InterfaceLog instance gets destroyed here and implicitly flushed
        ifc_log.reset();
    }

    // First line must be the request
    std::string content;
    std::getline(log_ifstream, content);
    CHECK(absl::StrContains(content, R"(REQ -> {"json":"2.0"})"));
    // No other content is present
    CHECK(log_ifstream.get() == -1);
    CHECK(log_ifstream.eof());
}

}  // namespace silkworm::rpc
