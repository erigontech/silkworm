/*
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
*/

#include "log.hpp"

#include <iostream>
#include <string>
#include <thread>

#include <absl/strings/match.h>
#include <catch2/catch.hpp>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::log {

//! Custom LogBuffer just for testing to access buffered content
template <Level level>
class LogBuffer_ForTest : public LogBuffer<level> {
  public:
    explicit LogBuffer_ForTest() : LogBuffer<level>() {}
    explicit LogBuffer_ForTest(std::string_view msg, Args args) : LogBuffer<level>(msg, args) {}

    [[nodiscard]] std::string content() const { return LogBuffer<level>::ss_.str(); }
};

//! Utility test function enforcing that log buffered content *IS* empty
template <Level level>
void check_log_empty() {
    auto log_buffer = LogBuffer_ForTest<level>();
    log_buffer << "test";
    CHECK(log_buffer.content().empty());
}

//! Utility test function enforcing that log buffered content *IS NOT* empty
template <Level level>
void check_log_not_empty() {
    auto log_buffer = LogBuffer_ForTest<level>();
    log_buffer << "test";
    CHECK(absl::StrContains(log_buffer.content(), "test"));
}

//! Build the plain key-value pair
static std::string key_value(const std::string& key, const std::string& value) {
    std::string kv_pair{key};
    kv_pair.append("=");
    kv_pair.append(value);
    return kv_pair;
}

//! Build the prettified key-value pair using color scheme
static std::string prettified_key_value(const std::string& key, const std::string& value) {
    std::string kv_pair{kColorGreen};
    kv_pair.append(key);
    kv_pair.append(kColorReset);
    kv_pair.append("=");
    kv_pair.append(kColorReset);
    kv_pair.append(kColorWhite);
    kv_pair.append(value);
    return kv_pair;
}

TEST_CASE("LogBuffer", "[silkworm][common][log]") {
    // Temporarily override std::cout and std::cerr with string streams to avoid terminal output
    std::stringstream string_cout, string_cerr;
    test_util::StreamSwap cout_swap{std::cout, string_cout};
    test_util::StreamSwap cerr_swap{std::cerr, string_cerr};
    // Make sure logging facility is initialized
    init();

    SECTION("LogBuffer stores nothing for verbosity higher than default") {
        check_log_empty<Level::kDebug>();
        check_log_empty<Level::kTrace>();
    }

    SECTION("LogBuffer stores content for verbosity lower than or equal to default") {
        check_log_not_empty<Level::kInfo>();
        check_log_not_empty<Level::kWarning>();
        check_log_not_empty<Level::kError>();
        check_log_not_empty<Level::kCritical>();
        check_log_not_empty<Level::kNone>();
    }

    SECTION("LogBuffer stores nothing for verbosity higher than configured one") {
        test_util::SetLogVerbosityGuard guard{Level::kWarning};
        check_log_empty<Level::kInfo>();
        check_log_empty<Level::kDebug>();
        check_log_empty<Level::kTrace>();
    }

    SECTION("LogBuffer stores content for verbosity lower than or equal to configured one") {
        test_util::SetLogVerbosityGuard guard{Level::kWarning};
        check_log_not_empty<Level::kWarning>();
        check_log_not_empty<Level::kError>();
        check_log_not_empty<Level::kCritical>();
        check_log_not_empty<Level::kNone>();
    }

    SECTION("Settings enable/disable thread tracing") {
        // Default thread tracing
        std::stringstream thread_id_stream;
        thread_id_stream << std::this_thread::get_id();
        auto log_buffer1 = LogBuffer_ForTest<Level::kInfo>();
        log_buffer1 << "test";
        CHECK(!absl::StrContains(log_buffer1.content(), thread_id_stream.str()));

        // Enable thread tracing
        Settings log_settings;
        log_settings.log_threads = true;
        init(log_settings);
        auto log_buffer2 = LogBuffer_ForTest<Level::kInfo>();
        log_buffer2 << "test";
        CHECK(absl::StrContains(log_buffer2.content(), thread_id_stream.str()));

        // Disable thread tracing
        log_settings.log_threads = false;
        init(log_settings);
        auto log_buffer3 = LogBuffer_ForTest<Level::kInfo>();
        log_buffer3 << "test";
        CHECK(!absl::StrContains(log_buffer3.content(), thread_id_stream.str()));
    }

    SECTION("Settings disable colorized output if log file present") {
        // Default output is colorized
        LogBuffer_ForTest<Level::kInfo>{"test0", {"key1", "value1", "key2", "value2"}};  // temporary log object, flush on dtor
        const auto cerr_output0{string_cerr.str()};
        CHECK(absl::StrContains(cerr_output0, "test0"));
        CHECK(!absl::StrContains(cerr_output0, key_value("key1", "value1")));
        CHECK(!absl::StrContains(cerr_output0, key_value("key2", "value2")));
        CHECK(absl::StrContains(cerr_output0, prettified_key_value("key1", "value1")));
        CHECK(absl::StrContains(cerr_output0, prettified_key_value("key2", "value2")));

        // Reset cerr replacement stream
        string_cerr.str("");
        string_cerr.clear();

        // Log file setting forcibly disables colors
        const auto temp_file{TemporaryDirectory::get_unique_temporary_path()};
        Settings log_settings1{
            .log_file = temp_file.string(),
        };
        init(log_settings1);
        LogBuffer_ForTest<Level::kInfo>{"test1", {"key1", "value1", "key2", "value2"}};  // temporary log object, flush on dtor
        const auto cerr_output1{string_cerr.str()};
        CHECK(absl::StrContains(cerr_output1, "test1"));
        CHECK(absl::StrContains(cerr_output1, key_value("key1", "value1")));
        CHECK(absl::StrContains(cerr_output1, key_value("key2", "value2")));
        CHECK(!absl::StrContains(cerr_output1, prettified_key_value("key1", "value1")));
        CHECK(!absl::StrContains(cerr_output1, prettified_key_value("key2", "value2")));

        // Reset cerr replacement stream
        string_cerr.str("");
        string_cerr.clear();

        // Log file setting forcibly disables colors even if explicitly set
        Settings log_settings2{
            .log_nocolor = false,  // try to enable colorized output
            .log_file = temp_file.string(),
        };
        init(log_settings2);
        LogBuffer_ForTest<Level::kInfo>{"test2", {"key3", "value3", "key4", "value4"}};  // temporary log object, flush on dtor
        const auto cerr_output2{string_cerr.str()};
        CHECK(absl::StrContains(cerr_output2, "test2"));
        CHECK(absl::StrContains(cerr_output2, key_value("key3", "value3")));
        CHECK(absl::StrContains(cerr_output2, key_value("key4", "value4")));
        CHECK(!absl::StrContains(cerr_output2, prettified_key_value("key3", "value3")));
        CHECK(!absl::StrContains(cerr_output2, prettified_key_value("key4", "value4")));
    }

    SECTION("Variable arguments: constructor") {
        auto log_buffer = LogBuffer_ForTest<Level::kInfo>("test", {"key1", "value1", "key2", "value2"});
        CHECK(absl::StrContains(log_buffer.content(), "test"));
        CHECK(absl::StrContains(log_buffer.content(), prettified_key_value("key1", "value1")));
        CHECK(absl::StrContains(log_buffer.content(), prettified_key_value("key2", "value2")));
    }

    SECTION("Variable arguments: accumulators") {
        auto log_buffer = LogBuffer_ForTest<Level::kInfo>();
        log_buffer << "test" << Args{"key1", "value1", "key2", "value2"};
        CHECK(absl::StrContains(log_buffer.content(), "test"));
        CHECK(absl::StrContains(log_buffer.content(), prettified_key_value("key1", "value1")));
        CHECK(absl::StrContains(log_buffer.content(), prettified_key_value("key2", "value2")));
    }
}

}  // namespace silkworm::log
