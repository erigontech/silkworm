// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "log.hpp"

#include <iostream>
#include <string>
#include <thread>

#include <absl/strings/match.h>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::log {

//! Custom LogBuffer just for testing to access buffered content
template <Level level>
class LogBufferForTest : public LogBuffer<level> {
  public:
    explicit LogBufferForTest() : LogBuffer<level>() {}
    explicit LogBufferForTest(std::string_view msg, const Args& args) : LogBuffer<level>(msg, args) {}

    std::string content() const { return LogBuffer<level>::ss_.str(); }
};

//! Utility test function enforcing that log buffered content *IS* empty
template <Level level>
void check_log_empty() {
    auto log_buffer = LogBufferForTest<level>();
    log_buffer << "test";
    CHECK(log_buffer.content().empty());
}

//! Utility test function enforcing that log buffered content *IS NOT* empty
template <Level level>
void check_log_not_empty() {
    auto log_buffer = LogBufferForTest<level>();
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
    // After the test restore verbosity as it was before the test
    test_util::SetLogVerbosityGuard log_guard{get_verbosity()};

    // Temporarily override std::cout and std::cerr with string streams to avoid terminal output
    std::stringstream string_cout, string_cerr;
    test_util::StreamSwap cout_swap{std::cout, string_cout};
    test_util::StreamSwap cerr_swap{std::cerr, string_cerr};
    // Make sure logging facility is initialized
    Settings settings{.log_verbosity = Level::kInfo};
    init(settings);

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
        auto log_buffer1 = LogBufferForTest<Level::kInfo>();
        log_buffer1 << "test";
        CHECK(!absl::StrContains(log_buffer1.content(), thread_id_stream.str()));

        // Enable thread tracing
        Settings log_settings{.log_verbosity = Level::kInfo};
        log_settings.log_threads = true;
        init(log_settings);
        auto log_buffer2 = LogBufferForTest<Level::kInfo>();
        log_buffer2 << "test";
        CHECK(absl::StrContains(log_buffer2.content(), thread_id_stream.str()));

        // Disable thread tracing
        log_settings.log_threads = false;
        init(log_settings);
        auto log_buffer3 = LogBufferForTest<Level::kInfo>();
        log_buffer3 << "test";
        CHECK(!absl::StrContains(log_buffer3.content(), thread_id_stream.str()));
    }

    SECTION("Settings disables colorized output depending on TTY") {
        const bool is_terminal = is_terminal_stdout() && is_terminal_stderr();

        // Default output is NOT colorized on non-TTY terminal
        LogBufferForTest<Level::kInfo>{"test0", {"key1", "value1", "key2", "value2"}};  // temporary log object, flush on dtor
        const auto cerr_output0{string_cerr.str()};
        CHECK(absl::StrContains(cerr_output0, "test0"));
        CHECK(absl::StrContains(cerr_output0, key_value("key1", "value1")) == !is_terminal);
        CHECK(absl::StrContains(cerr_output0, key_value("key2", "value2")) == !is_terminal);
        CHECK(absl::StrContains(cerr_output0, prettified_key_value("key1", "value1")) == is_terminal);
        CHECK(absl::StrContains(cerr_output0, prettified_key_value("key2", "value2")) == is_terminal);

        // Reset cerr replacement stream
        string_cerr.str("");
        string_cerr.clear();

        // Log file setting forcibly disables colors even if explicitly set
        Settings log_settings2{
            .log_nocolor = false,  // try to enable colorized output
            .log_verbosity = Level::kInfo,
        };
        init(log_settings2);
        LogBufferForTest<Level::kInfo>{"test2", {"key3", "value3", "key4", "value4"}};  // temporary log object, flush on dtor
        const auto cerr_output2{string_cerr.str()};
        CHECK(absl::StrContains(cerr_output2, "test2"));
        CHECK(absl::StrContains(cerr_output2, key_value("key3", "value3")) == !is_terminal);
        CHECK(absl::StrContains(cerr_output2, key_value("key4", "value4")) == !is_terminal);
        CHECK(absl::StrContains(cerr_output2, prettified_key_value("key3", "value3")) == is_terminal);
        CHECK(absl::StrContains(cerr_output2, prettified_key_value("key4", "value4")) == is_terminal);
    }

    SECTION("Settings disable colorized output if log file present") {
        const auto temp_file{TemporaryDirectory::get_unique_temporary_path()};

        // Log file setting forcibly disables colors even if explicitly set
        Settings log_settings2{
            .log_nocolor = false,  // try to enable colorized output
            .log_verbosity = Level::kInfo,
            .log_file = temp_file.string(),
        };
        init(log_settings2);
        LogBufferForTest<Level::kInfo>{"test2", {"key3", "value3", "key4", "value4"}};  // temporary log object, flush on dtor
        const auto cerr_output2{string_cerr.str()};
        CHECK(absl::StrContains(cerr_output2, "test2"));
        CHECK(absl::StrContains(cerr_output2, key_value("key3", "value3")));
        CHECK(absl::StrContains(cerr_output2, key_value("key4", "value4")));
        CHECK(!absl::StrContains(cerr_output2, prettified_key_value("key3", "value3")));
        CHECK(!absl::StrContains(cerr_output2, prettified_key_value("key4", "value4")));
    }

    SECTION("Variable arguments: constructor") {
        auto log_buffer = LogBufferForTest<Level::kInfo>("test", {"key1", "value1", "key2", "value2"});
        CHECK(absl::StrContains(log_buffer.content(), "test"));
        CHECK(absl::StrContains(log_buffer.content(), prettified_key_value("key1", "value1")));
        CHECK(absl::StrContains(log_buffer.content(), prettified_key_value("key2", "value2")));
    }

    SECTION("Variable arguments: accumulators") {
        auto log_buffer = LogBufferForTest<Level::kInfo>();
        log_buffer << "test" << Args{"key1", "value1", "key2", "value2"};
        CHECK(absl::StrContains(log_buffer.content(), "test"));
        CHECK(absl::StrContains(log_buffer.content(), prettified_key_value("key1", "value1")));
        CHECK(absl::StrContains(log_buffer.content(), prettified_key_value("key2", "value2")));
    }
}

#ifdef SILKWORM_TEST_SKIP
TEST_CASE("SILK_LOGBUFFER", "[silkworm][common][log]") {
    Settings settings{.log_verbosity = Level::kTrace};
    init(settings);

    log::Trace() << "hello using log::Trace";
    log::Debug() << "hello using log::Debug";
    log::Info() << "hello using log::Info";
    log::Warning() << "hello using log::Warning";
    log::Error() << "hello using log::Error";
    log::Critical() << "hello using log::Critical";
    log::Message() << "hello using log::Message";

    log::Trace("log_test") << "hello using log::Trace(\"log_test\")";
    log::Debug("log_test") << "hello using log::Debug(\"log_test\")";
    log::Info("log_test") << "hello using log::Info(\"log_test\")";
    log::Warning("log_test") << "hello using log::Warning(\"log_test\")";
    log::Error("log_test") << "hello using log::Error(\"log_test\")";
    log::Critical("log_test") << "hello using log::Critical(\"log_test\")";
    log::Message("log_test") << "hello using log::Message(\"log_test\")";

    SILK_TRACE << "hello using SILK_TRACE";
    SILK_DEBUG << "hello using SILK_DEBUG";
    SILK_INFO << "hello using SILK_INFO";
    SILK_WARN << "hello using SILK_WARN";
    SILK_ERROR << "hello using SILK_ERROR";
    SILK_CRIT << "hello using SILK_CRIT";
    SILK_LOG << "hello using SILK_LOG";

    SILK_TRACE_M("log_test") << "hello using SILK_TRACE_M(\"log_test\")";
    SILK_DEBUG_M("log_test") << "hello using SILK_DEBUG_M(\"log_test\")";
    SILK_INFO_M("log_test") << "hello using SILK_INFO_M(\"log_test\")";
    SILK_WARN_M("log_test") << "hello using SILK_WARN_M(\"log_test\")";
    SILK_ERROR_M("log_test") << "hello using SILK_ERROR_M(\"log_test\")";
    SILK_CRIT_M("log_test") << "hello using SILK_CRIT_M(\"log_test\")";
    SILK_LOG_M("log_test") << "hello using SILK_LOG_M(\"log_test\")";
}
#endif  // SILKWORM_TEST_SKIP

}  // namespace silkworm::log
