// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "log.hpp"

#include <fstream>
#include <iostream>
#include <mutex>
#include <ostream>
#include <regex>
#include <stdexcept>
#include <thread>

#include <absl/log/globals.h>
#include <absl/log/initialize.h>
#include <absl/strings/ascii.h>
#include <absl/time/clock.h>

#include <silkworm/infra/grpc/common/util.hpp>

namespace silkworm::log {

//! The fixed size for thread name in log traces
static constexpr size_t kThreadNameFixedSize = 11;

static Settings settings_{};
static std::mutex out_mtx{};
static std::unique_ptr<std::fstream> file_{nullptr};
static bool is_terminal{false};
thread_local std::string thread_name_{};
static std::optional<AbseilLogGuard<log::AbseilToSilkwormLogSink>> absl_log_guard;
static std::once_flag absl_log_init_once_flag;

void init(const Settings& settings) {
    settings_ = settings;
    if (!settings_.log_file.empty()) {
        tee_file(std::filesystem::path(settings.log_file));
        // Forcibly disable colorized output to avoid escape char sequences into log file
        settings_.log_nocolor = true;
    }

    absl::SetMinLogLevel(settings.log_grpc ? absl_min_log_level_from_silkworm(settings.log_verbosity) : absl::LogSeverityAtLeast::kInfinity);
    absl::SetGlobalVLogLevel(settings.log_grpc ? absl_max_vlog_level_from_silkworm(settings.log_verbosity) : -1);
    absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfinity);
    if (settings.log_grpc) {
        absl_log_guard.emplace();
    } else {
        absl_log_guard = std::nullopt;
    }
    std::call_once(absl_log_init_once_flag, absl::InitializeLog);

    init_terminal();
    is_terminal = settings_.log_std_out ? is_terminal_stdout() : is_terminal_stderr();
    settings_.log_nocolor = settings_.log_nocolor || !is_terminal;
}

void tee_file(const std::filesystem::path& path) {
    file_ = std::make_unique<std::fstream>(path.string(), std::ios::out | std::ios::app);
    if (!file_->is_open()) {
        file_.reset();
        throw std::runtime_error("Could not open file " + path.string());
    }
}

Level get_verbosity() { return settings_.log_verbosity; }

void set_verbosity(Level level) { settings_.log_verbosity = level; }

bool test_verbosity(Level level) { return level <= settings_.log_verbosity; }

//! Set the current thread name resizing it to a fixed size
void set_thread_name(const char* name) {
    thread_name_ = std::string(name);
    thread_name_.resize(kThreadNameFixedSize, ' ');
}

std::string get_thread_name() {
    if (thread_name_.empty()) {
        std::stringstream ss;
        ss << std::this_thread::get_id();
        thread_name_ = ss.str();
    }
    return thread_name_;
}

static std::pair<std::string_view, std::string_view> get_level_settings(Level level) {
    switch (level) {
        case Level::kTrace:
            return {"TRACE", kColorCoal};
        case Level::kDebug:
            return {"DEBUG", kBackgroundPurple};
        case Level::kInfo:
            return {" INFO", kColorGreen};
        case Level::kWarning:
            return {" WARN", kColorOrangeHigh};
        case Level::kError:
            return {"ERROR", kColorRed};
        case Level::kCritical:
            return {" CRIT", kBackgroundRed};
        default:
            return {"     ", kColorReset};
    }
}

struct SeparateThousands : std::numpunct<char> {
    char separator;
    explicit SeparateThousands(char sep) : separator(sep) {}
    char do_thousands_sep() const override { return separator; }
    string_type do_grouping() const override { return "\3"; }  // groups of 3 digit
};

void prepare_for_logging(std::ostream& ss) {
    if (settings_.log_thousands_sep != 0) {
        ss.imbue(std::locale(ss.getloc(), new SeparateThousands(settings_.log_thousands_sep)));
    }
}

BufferBase::BufferBase(Level level) : should_print_(level <= settings_.log_verbosity) {
    if (!should_print_) return;

    if (settings_.log_thousands_sep != 0) {
        ss_.imbue(std::locale(ss_.getloc(), new SeparateThousands(settings_.log_thousands_sep)));
    }

    auto [log_level, color] = get_level_settings(level);

    // Prefix
    auto log_tag{settings_.log_trim ? absl::StripAsciiWhitespace(log_level).substr(0, 4) : log_level};
    std::string_view padding = settings_.log_trim ? "" : " ";
    ss_ << kColorReset
        << (settings_.log_trim && !is_terminal ? "[" : padding) << color << log_tag
        << kColorReset
        << (settings_.log_trim && !is_terminal ? "] " : padding);

    // TimeStamp
    static const absl::TimeZone kTz{settings_.log_utc ? absl::UTCTimeZone() : absl::LocalTimeZone()};
    absl::Time now{absl::Now()};

    auto log_timezone{settings_.log_timezone ? std::string{" "} + kTz.name() : ""};
    ss_ << kColorWhite << "[" << absl::FormatTime("%m-%d|%H:%M:%E3S", now, kTz) << log_timezone << "] " << kColorReset;

    // ThreadId
    if (settings_.log_threads) {
        ss_ << "[" << get_thread_name() << "] ";
    }
}

BufferBase::BufferBase(Level level, std::string_view msg, const Args& args) : BufferBase(level) {
    append(msg, args);
}

void BufferBase::flush() {
    if (!should_print_) return;

    // Pattern to identify colorization
    static const std::regex kColorPattern("(\\\x1b\\[[0-9;]{1,}m)");

    bool colorized{true};
    std::string line{ss_.str()};
    if (settings_.log_nocolor) {
        line = std::regex_replace(line, kColorPattern, "");
        colorized = false;
    }
    std::scoped_lock out_lck{out_mtx};
    auto& out = settings_.log_std_out ? std::cout : std::cerr;
    out << line << '\n';
    if (file_ && file_->is_open()) {
        if (colorized) {
            line = std::regex_replace(line, kColorPattern, "");
        }
        *file_ << line << '\n';
    }
}

}  // namespace silkworm::log
