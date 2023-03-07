/*
   Copyright 2020 The Silkrpc Authors

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

#include <string>
#include <thread>

#include <absl/strings/str_cat.h>
#include <absl/time/clock.h>

#include <silkworm/silkrpc/common/tee.hpp>

namespace silkrpc {

constexpr char const kLogTags_[7][6] = {
    "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "CRIT ", "NONE ",
};

teestream log_streams_{std::cerr, null_stream()};

LogLevel log_verbosity_{LogLevel::Info};
bool log_thread_enabled_{false};

// Log to one or two output streams - typically the console and optional log file.
void log_set_streams_(std::ostream& o1, std::ostream& o2) { log_streams_.set_streams(o1.rdbuf(), o2.rdbuf()); }

std::mutex log_::log_mtx_;

std::ostream& log_::header_(LogLevel level) {
    log_streams_ << kLogTags_[static_cast<int>(level)] << "["
                 << absl::FormatTime("%m-%d|%H:%M:%E3S", absl::Now(), absl::LocalTimeZone()) << "]";
    if (log_thread_enabled_) {
        log_streams_ << " " << std::this_thread::get_id();
    }
    return log_streams_;
}

std::ostream& null_stream() {
    static struct null_buf : public std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;
    static struct null_strm : public std::ostream {
        null_strm() : std::ostream(&null_buf) {}
    } null_strm;
    return null_strm;
}

bool AbslParseFlag(absl::string_view text, LogLevel* level, std::string* error) {
    if (text == "n") {
        *level = LogLevel::None;
        return true;
    }
    if (text == "c") {
        *level = LogLevel::Critical;
        return true;
    }
    if (text == "e") {
        *level = LogLevel::Error;
        return true;
    }
    if (text == "w") {
        *level = LogLevel::Warn;
        return true;
    }
    if (text == "i") {
        *level = LogLevel::Info;
        return true;
    }
    if (text == "d") {
        *level = LogLevel::Debug;
        return true;
    }
    if (text == "t") {
        *level = LogLevel::Trace;
        return true;
    }
    *error = "unknown value for LogLevel";
    return false;
}

std::string AbslUnparseFlag(LogLevel level) {
    switch (level) {
        case LogLevel::None: return "n";
        case LogLevel::Critical: return "c";
        case LogLevel::Error: return "e";
        case LogLevel::Warn: return "w";
        case LogLevel::Info: return "i";
        case LogLevel::Debug: return "d";
        case LogLevel::Trace: return "t";
        default: return absl::StrCat(level);
    }
}

} // namespace silkrpc
