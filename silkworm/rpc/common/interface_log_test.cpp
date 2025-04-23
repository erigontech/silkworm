// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
        .auto_flush = false,
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
        .auto_flush = false,
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

TEST_CASE("InterfaceLog dump: two instances w/o auto-flush", "[rpc][common][interface_log]") {
    const auto tmp_dir{TemporaryDirectory::get_unique_temporary_path()};
    InterfaceLogSettings settings{
        .enabled = true,
        .ifc_name = "eth_rpc",
        .container_folder = tmp_dir,
        .auto_flush = false,
    };
    auto ifc_log1 = std::make_unique<InterfaceLog>(settings);
    auto ifc_log2 = std::make_unique<InterfaceLog>(settings);
    REQUIRE(ifc_log1->path() == ifc_log2->path());

    std::ifstream log_ifstream{ifc_log1->path().string()};

    static constexpr size_t kLogBufferSize{1024 * 4};
    static const size_t kLogLineHeaderSize{InterfaceLog::kLogLineHeaderSize};

    std::string request1;
    std::string request2(100, 'B');  // always less than page size

    SECTION("less than page size") {
        request1.assign(kLogBufferSize - kLogLineHeaderSize - 1 /*\n*/ - 1, 'A');

        SECTION("same instance") {
            // Logging request1 is NOT sufficient to trigger page write w/o flush
            ifc_log1->log_req(request1);
            CHECK(std::filesystem::file_size(ifc_log1->path()) == 0);

            // Logging request2 crosses the page size, so one page is written w/o flush
            ifc_log1->log_req(request2);
            CHECK(std::filesystem::file_size(ifc_log1->path()) == kLogBufferSize);

            // Flushing writes the whole write buffer content
            ifc_log1->flush();

            // Log file content is exactly log_line_header + request1 + log_line_header + request2
            std::string content;
            std::getline(log_ifstream, content);
            CHECK(content.substr(kLogLineHeaderSize) == request1);
            std::getline(log_ifstream, content);
            CHECK(content.substr(kLogLineHeaderSize) == request2);
        }
        SECTION("different instances") {
            // Logging request1 through ifc_log1 is NOT sufficient to trigger page write w/o flush
            ifc_log1->log_req(request1);
            CHECK(std::filesystem::file_size(ifc_log1->path()) == 0);

            // Logging request2 through ifc_log2 DOES NOT trigger page write: write buffers are separate
            ifc_log2->log_req(request2);
            CHECK(std::filesystem::file_size(ifc_log2->path()) == 0);

            // Flushing both instances dumps the separate write buffers in order
            ifc_log2->flush();
            ifc_log1->flush();

            // Log file content is exactly log_line_header + request2 + log_line_header + request1
            std::string content;
            std::getline(log_ifstream, content);
            CHECK(content.substr(kLogLineHeaderSize) == request2);
            std::getline(log_ifstream, content);
            CHECK(content.substr(kLogLineHeaderSize) == request1);
        }
        // No other content is present
        CHECK(log_ifstream.get() == -1);
        CHECK(log_ifstream.eof());

        CHECK(std::filesystem::file_size(ifc_log1->path()) ==
              (request1.size() + kLogLineHeaderSize + 1) +
                  (request2.size() + kLogLineHeaderSize + 1));
    }

    SECTION("greater than or equal to page size") {
        request1.assign(4096 - kLogLineHeaderSize + 1, 'A');

        SECTION("same instance") {
            // Logging request1 is sufficient to trigger page write w/o flush
            ifc_log1->log_req(request1);
            CHECK(std::filesystem::file_size(ifc_log1->path()) == kLogBufferSize);

            // Logging request2 DOES NOT trigger another page write
            ifc_log1->log_req(request2);
            CHECK(std::filesystem::file_size(ifc_log1->path()) == kLogBufferSize);

            // Flushing writes the whole write buffer content
            ifc_log1->flush();

            // Log file content is exactly log_line_header + request1 + log_line_header + request2
            std::string content;
            std::getline(log_ifstream, content);
            CHECK(content.substr(kLogLineHeaderSize) == request1);
            std::getline(log_ifstream, content);
            CHECK(content.substr(kLogLineHeaderSize) == request2);
        }
        SECTION("different instances w/o flush: possible truncation") {
            // Logging request1 through ifc_log1 is sufficient to trigger page write w/o flush
            ifc_log1->log_req(request1);
            CHECK(std::filesystem::file_size(ifc_log1->path()) == kLogBufferSize);

            // Logging request2 through ifc_log2 DOES NOT trigger another page write
            ifc_log2->log_req(request2);
            CHECK(std::filesystem::file_size(ifc_log2->path()) == kLogBufferSize);

            // Flushing ifc_log2 BEFORE ifc_log1 generates a mixed content: truncated request1 + request2
            ifc_log2->flush();

            // Log file content is exactly log_line_header + request1 TRUNCATED AT 4k + log_line_header + request2
            std::string content;
            std::getline(log_ifstream, content);
            CHECK(content.substr(0, kLogLineHeaderSize).ends_with("REQ -> "));
            CHECK(content.substr(kLogLineHeaderSize, kLogBufferSize - kLogLineHeaderSize) == std::string(kLogBufferSize - kLogLineHeaderSize, 'A'));
            CHECK(content.substr(kLogBufferSize, kLogLineHeaderSize).ends_with("REQ -> "));
            CHECK(content.substr(kLogBufferSize + kLogLineHeaderSize) == request2);
        }
        SECTION("different instances w/ flush: no truncation") {
            // Logging request1 through ifc_log1 and flushing
            ifc_log1->log_req(request1);
            ifc_log1->flush();
            CHECK(std::filesystem::file_size(ifc_log1->path()) == request1.size() + kLogLineHeaderSize + 1);

            // Logging request2 through ifc_log2 and flushing
            ifc_log2->log_req(request2);
            ifc_log2->flush();
            CHECK(std::filesystem::file_size(ifc_log2->path()) ==
                  (request1.size() + kLogLineHeaderSize + 1) +
                      (request2.size() + kLogLineHeaderSize + 1));

            // Log file content is exactly log_line_header + request2 + log_line_header + request1
            std::string content;
            std::getline(log_ifstream, content);
            CHECK(content.substr(kLogLineHeaderSize) == request1);
            std::getline(log_ifstream, content);
            CHECK(content.substr(kLogLineHeaderSize) == request2);
        }
        // No other content is present
        CHECK(log_ifstream.get() == -1);
        CHECK(log_ifstream.eof());
    }
}

TEST_CASE("InterfaceLog dump: two instances w/ auto-flush", "[rpc][common][interface_log]") {
    const auto tmp_dir{TemporaryDirectory::get_unique_temporary_path()};
    InterfaceLogSettings settings{
        .enabled = true,
        .ifc_name = "eth_rpc",
        .container_folder = tmp_dir,
    };
    auto ifc_log1 = std::make_unique<InterfaceLog>(settings);
    auto ifc_log2 = std::make_unique<InterfaceLog>(settings);
    REQUIRE(ifc_log1->path() == ifc_log2->path());

    static constexpr size_t kLogBufferSize{1024 * 4};
    static const size_t kLogLineHeaderSize{InterfaceLog::kLogLineHeaderSize};

    std::string request1;
    std::string request2(100, 'B');  // always less than page size

    SECTION("less than page size") {
        request1.assign(kLogBufferSize - kLogLineHeaderSize - 1 /*\n*/ - 1, 'A');
    }

    SECTION("greater than or equal to page size") {
        request1.assign(4096 - kLogLineHeaderSize + 1, 'A');
    }

    // Logging request1 through ifc_log1 implicitly flushes
    ifc_log1->log_req(request1);
    CHECK(std::filesystem::file_size(ifc_log1->path()) == request1.size() + kLogLineHeaderSize + 1);

    // Logging request2 through ifc_log2 implicitly flushes
    ifc_log2->log_req(request2);
    CHECK(std::filesystem::file_size(ifc_log2->path()) ==
          (request1.size() + kLogLineHeaderSize + 1) +
              (request2.size() + kLogLineHeaderSize + 1));

    // Log file content is exactly log_line_header + request1 + log_line_header + request2
    std::ifstream log_ifstream{ifc_log1->path().string()};
    std::string content;
    std::getline(log_ifstream, content);
    CHECK(content.substr(kLogLineHeaderSize) == request1);
    std::getline(log_ifstream, content);
    CHECK(content.substr(kLogLineHeaderSize) == request2);

    // No other content is present
    CHECK(log_ifstream.get() == -1);
    CHECK(log_ifstream.eof());
}

}  // namespace silkworm::rpc
