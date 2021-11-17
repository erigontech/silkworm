/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <thread>

#include <absl/time/clock.h>

#include <silkworm/common/log.hpp>

#include "terminal.hpp"

namespace silkworm::log {

std::ostream& null_stream() {
    static struct null_buf : public std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;
    static struct null_strm : public std::ostream {
        null_strm() : std::ostream(&null_buf) {}
    } null_strm;
    return null_strm;
}

static TeeStream log_streams_{std::clog, null_stream()};

LogLevel log_verbosity_{LogLevel::Info};
bool log_thread_enabled_{false};
bool log_utc_{false};

// Log to one or two output streams - typically the console and optional log file.
void log_set_streams_(std::ostream& o1, std::ostream& o2) { log_streams_.set_streams(o1.rdbuf(), o2.rdbuf()); }
void set_verbosity(LogLevel level) { log_verbosity_ = level; }

static inline std::pair<const char*, const char*> get_channel_settings(LogLevel level) {
    switch (level) {
        case LogLevel::Trace:
            return {"TRACE", kColorCoal};
        case LogLevel::Debug:
            return {"DEBUG", kBackgroundPurple};
        case LogLevel::Info:
            return {" INFO", kColorGreen};
        case LogLevel::Warn:
            return {" WARN", kColorOrangeHigh};
        case LogLevel::Error:
            return {"ERROR", kColorRed};
        case LogLevel::Critical:
            return {" CRIT", kBackgroundRed};
        default:
            return {"     ", kColorReset};
    }
}

LogBufferBase::LogBufferBase(LogLevel level) : level_(level) {
    auto [prefix, color] = get_channel_settings(level);
    // Prefix
    ss_ << kColorReset << " " << color << prefix << kColorReset << " ";

    // TimeStamp
    static const absl::TimeZone tz{log_utc_ ? absl::LocalTimeZone() : absl::UTCTimeZone()};
    absl::Time now{absl::Now()};
    ss_ << kColorCyan << "[" << absl::FormatTime("%m-%d|%H:%M:%E3S", now, tz) << " " << tz << "] " << kColorReset;

    // ThreadId
    if (log_thread_enabled_) {
        ss_ << " [" << std::this_thread::get_id() << "] ";
    }
}

void LogBufferBase::flush() {
    if (level_ >= log_verbosity_) {
        log_streams_ << ss_.str() << std::endl;
    }
}

}  // namespace silkworm::log
