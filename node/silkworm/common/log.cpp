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

#include <fstream>
#include <iostream>
#include <ostream>
#include <regex>
#include <thread>

#include <absl/time/clock.h>

#include <silkworm/common/log.hpp>

#if defined(_WIN32)
#include <windows.h>
#if !defined(ENABLE_VIRTUAL_TERMINAL_PROCESSING)
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#endif

namespace silkworm::log {

static Settings settings_{};

static std::unique_ptr<std::fstream> file_{nullptr};

void init(Settings& settings) {
    settings_ = settings;
    if (!settings_.log_file.empty()) {
        tee_file(std::filesystem::path(settings.log_file));
    }

#if defined(_WIN32)
    // Change code page to UTF-8 so log characters are displayed correctly in console
    // and also support virtual terminal processing for coloring output
    SetConsoleOutputCP(CP_UTF8);
    HANDLE output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output_handle != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(output_handle, &mode)) {
            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(output_handle, mode);
        }
    }
#endif
}

void tee_file(std::filesystem::path path) {
    file_ = std::make_unique<std::fstream>(path.string(), std::ios::out | std::ios::app);
    if (!file_->is_open()) {
        file_.reset();
        throw std::runtime_error("Could not open file " + path.string());
    }
}

void set_verbosity(Level level) { settings_.log_verbosity = static_cast<unsigned>(level); }

static inline std::pair<const char*, const char*> get_channel_settings(Level level) {
    switch (level) {
        case Level::Trace:
            return {"TRACE", kColorCoal};
        case Level::Debug:
            return {"DEBUG", kBackgroundPurple};
        case Level::Info:
            return {" INFO", kColorGreen};
        case Level::Warn:
            return {" WARN", kColorOrangeHigh};
        case Level::Error:
            return {"ERROR", kColorRed};
        case Level::Critical:
            return {" CRIT", kBackgroundRed};
        default:
            return {"     ", kColorReset};
    }
}

BufferBase::BufferBase(Level level) : level_(level) {
    auto [prefix, color] = get_channel_settings(level);
    // Prefix
    ss_ << kColorReset << " " << color << prefix << kColorReset << " ";

    // TimeStamp
    static const absl::TimeZone tz{settings_.log_utc ? absl::LocalTimeZone() : absl::UTCTimeZone()};
    absl::Time now{absl::Now()};
    ss_ << kColorCyan << "[" << absl::FormatTime("%m-%d|%H:%M:%E3S", now, tz) << " " << tz << "] " << kColorReset;

    // ThreadId
    if (settings_.log_threads) {
        ss_ << "[" << std::this_thread::get_id() << "] ";
    }
}

void BufferBase::flush() {
    if (static_cast<unsigned>(level_) > settings_.log_verbosity) {
        return;
    }

    // Pattern to identify colorization
    static const std::regex color_pattern("(\\\x1b\\[[0-9;]{1,}m)");

    bool colorized{true};
    std::string line{ss_.str()};
    if (settings_.log_nocolor) {
        line = std::regex_replace(line, color_pattern, "");
        colorized = false;
    }
    auto& out = settings_.log_std_out ? std::cout : std::cerr;
    out << line << std::endl;
    if (file_ && file_->is_open()) {
        if (colorized) {
            line = std::regex_replace(line, color_pattern, "");
        }
        *file_ << line << std::endl;
    }
}

}  // namespace silkworm::log
