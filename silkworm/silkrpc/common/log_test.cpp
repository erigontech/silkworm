/*
   Copyright 2021 The Silkrpc Authors

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

#include "log.hpp"

#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <catch2/catch.hpp>

namespace silkrpc {

using Catch::Matchers::Message;

TEST_CASE("parse log level", "[silkrpc][common][log]") {
    std::vector<absl::string_view> input_texts{
        "n", "c", "e", "w", "i", "d", "t"
    };
    std::vector<LogLevel> expected_levels{
        LogLevel::None,
        LogLevel::Critical,
        LogLevel::Error,
        LogLevel::Warn,
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::Trace,
    };
    for (auto i{0}; i < input_texts.size(); i++) {
        LogLevel level;
        std::string error;
        const auto success{AbslParseFlag(input_texts[i], &level, &error)};
        CHECK(success == true);
        CHECK(error.empty());
        CHECK(level == expected_levels[i]);
    }
}

TEST_CASE("parse invalid log level", "[silkrpc][common][log]") {
    LogLevel level;
    std::string error;
    const auto success{AbslParseFlag("abc", &level, &error)};
    CHECK(success == false);
    CHECK(!error.empty());
}

TEST_CASE("unparse log level", "[silkrpc][common][log]") {
    std::vector<LogLevel> input_levels{
        LogLevel::None,
        LogLevel::Critical,
        LogLevel::Error,
        LogLevel::Warn,
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::Trace,
    };
    std::vector<absl::string_view> expected_texts{
        "n", "c", "e", "w", "i", "d", "t"
    };
    for (auto i{0}; i < input_levels.size(); i++) {
        const auto text{AbslUnparseFlag(input_levels[i])};
        CHECK(text == expected_texts[i]);
    }
}

TEST_CASE("LOG macro does nothing for lower verbosity", "[silkrpc][common][log]") {
    std::stringstream ss1;
    SILKRPC_LOG_STREAMS(ss1, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::Warn);
    LOG(LogLevel::Info) << "test";
    CHECK(ss1.str().empty());
}

TEST_CASE("LOG macro does output for higher or equal verbosity", "[silkrpc][common][log]") {
    std::stringstream ss1;
    SILKRPC_LOG_STREAMS(ss1, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::Warn);
    LOG(LogLevel::Warn) << "test";
    CHECK(ss1.str().find("WARN") != std::string::npos);
    CHECK(ss1.str().find("test") != std::string::npos);
    std::stringstream ss2;
    SILKRPC_LOG_STREAMS(ss2, null_stream());
    LOG(LogLevel::Critical) << "test";
    CHECK(ss2.str().find("CRIT") != std::string::npos);
    CHECK(ss2.str().find("test") != std::string::npos);
}

TEST_CASE("SILKRPC_TRACE macro uses level Trace", "[silkrpc][common][log]") {
    std::stringstream ss;
    SILKRPC_LOG_STREAMS(ss, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::Trace);
    SILKRPC_TRACE << "test";
    CHECK(ss.str().find("TRACE") != std::string::npos);
}

TEST_CASE("SILKRPC_DEBUG macro uses level Debug", "[silkrpc][common][log]") {
    std::stringstream ss;
    SILKRPC_LOG_STREAMS(ss, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::Debug);
    SILKRPC_DEBUG << "test";
    CHECK(ss.str().find("DEBUG") != std::string::npos);
}

TEST_CASE("SILKRPC_INFO macro uses level Info", "[silkrpc][common][log]") {
    std::stringstream ss;
    SILKRPC_LOG_STREAMS(ss, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::Info);
    SILKRPC_INFO << "test";
    CHECK(ss.str().find("INFO") != std::string::npos);
}

TEST_CASE("SILKRPC_WARN macro uses level Warn", "[silkrpc][common][log]") {
    std::stringstream ss;
    SILKRPC_LOG_STREAMS(ss, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::Warn);
    SILKRPC_WARN << "test";
    CHECK(ss.str().find("WARN") != std::string::npos);
}

TEST_CASE("SILKRPC_ERROR macro uses level Error", "[silkrpc][common][log]") {
    std::stringstream ss;
    SILKRPC_LOG_STREAMS(ss, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::Error);
    SILKRPC_ERROR << "test";
    CHECK(ss.str().find("ERROR") != std::string::npos);
}

TEST_CASE("SILKRPC_CRIT macro uses level Critical", "[silkrpc][common][log]") {
    std::stringstream ss;
    SILKRPC_LOG_STREAMS(ss, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::Critical);
    SILKRPC_CRIT << "test";
    CHECK(ss.str().find("CRIT") != std::string::npos);
}

TEST_CASE("SILKRPC_LOG macro uses level None", "[silkrpc][common][log]") {
    std::stringstream ss;
    SILKRPC_LOG_STREAMS(ss, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::None);
    SILKRPC_LOG << "test";
    CHECK(ss.str().find("NONE") != std::string::npos);
}

TEST_CASE("SILKRPC_LOG_THREAD macro enables/disables thread tracing", "[silkrpc][common][log]") {
    std::stringstream ss1;
    SILKRPC_LOG_STREAMS(ss1, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::None);
    SILKRPC_LOG_THREAD(true);
    SILKRPC_LOG << "test";
    std::stringstream thread_id_stream;
    thread_id_stream << std::this_thread::get_id();
    CHECK(ss1.str().find(thread_id_stream.str()) != std::string::npos);
    std::stringstream ss2;
    SILKRPC_LOG_STREAMS(ss2, null_stream());
    SILKRPC_LOG_THREAD(false);
    SILKRPC_LOG << "test";
    CHECK(ss2.str().find(thread_id_stream.str()) == std::string::npos);
}

} // namespace silkrpc

