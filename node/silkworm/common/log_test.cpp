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

#include <catch2/catch.hpp>

namespace silkworm::log {

// Custom LogBuffer just for testing to access buffered content
template <Level level>
class TestLogBuffer : public LogBuffer<level> {
  public:
    std::string content() const { return LogBuffer<level>::ss_.str(); }
};

// Utility test function enforcing that log buffered content *IS* empty
template <Level level>
void check_log_empty() {
    auto log_buffer = TestLogBuffer<level>();
    log_buffer << "test";
    CHECK(log_buffer.content().empty());
}

// Utility test function enforcing that log buffered content *IS NOT* empty
template <Level level>
void check_log_not_empty() {
    auto log_buffer = TestLogBuffer<level>();
    log_buffer << "test";
    CHECK(log_buffer.content().find("test") != std::string::npos);
}

// Utility class using RAII to swap the underlying buffers of the provided streams
class StreamSwap {
  public:
    StreamSwap(std::ostream& o1, std::ostream& o2) : buffer_(o1.rdbuf()), stream_(o1) { o1.rdbuf(o2.rdbuf()); }
    ~StreamSwap() { stream_.rdbuf(buffer_); }

  private:
    std::streambuf* buffer_;
    std::ostream& stream_;
};

// Factory function creating one null output stream (all characters are discarded)
std::ostream& null_stream() {
    static struct null_buf : public std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;
    static struct null_strm : public std::ostream {
        null_strm() : std::ostream(&null_buf) {}
    } null_strm;
    return null_strm;
}

TEST_CASE("LogBuffer", "[silkworm][common][log]") {
    // Temporarily override std::cout and std::cerr with null stream to avoid terminal output
    StreamSwap cout_swap{std::cout, null_stream()};
    StreamSwap cerr_swap{std::cerr, null_stream()};

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
        set_verbosity(Level::kWarning);
        check_log_empty<Level::kInfo>();
        check_log_empty<Level::kDebug>();
        check_log_empty<Level::kTrace>();
    }

    SECTION("LogBuffer stores content for verbosity lower than or equal to configured one") {
        set_verbosity(Level::kWarning);
        check_log_not_empty<Level::kWarning>();
        check_log_not_empty<Level::kError>();
        check_log_not_empty<Level::kCritical>();
        check_log_not_empty<Level::kNone>();
    }

    SECTION("Settings enable/disable thread tracing") {
        // Default thread tracing
        std::stringstream thread_id_stream;
        thread_id_stream << std::this_thread::get_id();
        auto log_buffer1 = TestLogBuffer<Level::kInfo>();
        log_buffer1 << "test";
        CHECK(log_buffer1.content().find(thread_id_stream.str()) == std::string::npos);

        // Enable thread tracing
        Settings log_settings;
        log_settings.log_threads = true;
        init(log_settings);
        auto log_buffer2 = TestLogBuffer<Level::kInfo>();
        log_buffer2 << "test";
        CHECK(log_buffer2.content().find(thread_id_stream.str()) != std::string::npos);

        // Disable thread tracing
        log_settings.log_threads = false;
        init(log_settings);
        auto log_buffer3 = TestLogBuffer<Level::kInfo>();
        log_buffer3 << "test";
        CHECK(log_buffer3.content().find(thread_id_stream.str()) == std::string::npos);
    }
}

}  // namespace silkworm::log
