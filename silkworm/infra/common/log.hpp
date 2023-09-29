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

#pragma once

#include <filesystem>
#include <sstream>
#include <vector>

#include <silkworm/infra/common/terminal.hpp>

namespace silkworm::log {

//! \brief Available verbosity levels
enum class Level {
    kNone,      // Simple logging line with no severity (e.g. build info)
    kCritical,  // An error there's no way we can recover from
    kError,     // We encountered an error which we might be able to recover from
    kWarning,   // Something happened and user might have the possibility to amend the situation
    kInfo,      // Info messages on regular operations
    kDebug,     // Debug information
    kTrace      // Trace calls to functions
};

//! \brief Holds logging configuration
struct Settings {
    bool log_std_out{false};            // Whether console logging goes to std::cout or std::cerr (default)
    bool log_utc{true};                 // Whether timestamps should be in UTC or imbue local timezone
    bool log_timezone{true};            // Whether timestamps should include the timezone identifier
    bool log_nocolor{false};            // Whether to disable colorized output
    bool log_trim{false};               // Whether to trim log level
    bool log_threads{false};            // Whether to print thread ids in log lines
    Level log_verbosity{Level::kInfo};  // Log verbosity level
    std::string log_file;               // Log to file
    char log_thousands_sep{'\''};       // Thousands separator
    bool log_grpc{true};                // Include GRPC library internal logs
};

//! \brief Initializes logging facilities
//! \note This function is not thread safe as it's meant to be used at start of process and never called again
void init(Settings& settings);

//! \brief Get the current logging verbosity
//! \note This function is not thread safe as it's meant to be used in tests
Level get_verbosity();

//! \brief Sets logging verbosity
//! \note This function is not thread safe as it's meant to be used at start of process and never called again
void set_verbosity(Level level);

//! \brief Sets the name for this thread when logging traces also threads
void set_thread_name(const char* name);

//! \brief Returns the currently set name for the thread or the thread id
std::string get_thread_name();

//! \brief Checks if provided log level will be effectively printed on behalf of current settings
//! \return True / False
//! \remarks Some logging operations may implement computations which would be completely wasted if the outcome is not
//! printed
bool test_verbosity(Level level);

//! \brief Sets a file output for log teeing
//! \note This function is not thread safe as it's meant to be used at start of process and never called again
void tee_file(const std::filesystem::path& path);

void prepare_for_logging(std::ostream&);

using Args = std::vector<std::string>;

class BufferBase {
  public:
    explicit BufferBase(Level level);
    explicit BufferBase(Level level, std::string_view msg, const Args& args);
    ~BufferBase() { flush(); }

    // Accumulators
    template <class T>
    inline void append(const T& t) {
        if (should_print_) ss_ << t;
    }
    template <class T>
    BufferBase& operator<<(const T& t) {
        append(t);
        return *this;
    }
    inline void append(const Args& args) {
        append("", args);
    }
    inline BufferBase& operator<<(const Args& args) {
        append(args);
        return *this;
    }

  protected:
    inline void append(std::string_view msg, const Args& args) {
        if (!should_print_) return;
        ss_ << std::left << std::setw(41) << std::setfill(' ') << msg;
        bool left{true};
        for (const auto& arg : args) {
            ss_ << (left ? kColorGreen : kColorWhite) << arg << kColorReset << (left ? "=" : " ") << kColorReset;
            left = !left;
        }
    }
    void flush();
    const bool should_print_;
    std::stringstream ss_;
};

template <Level level>
class LogBuffer : public BufferBase {
  public:
    explicit LogBuffer() : BufferBase(level) {}
    explicit LogBuffer(std::string_view msg, Args args = {}) : BufferBase(level, msg, args) {}
};

using Trace = LogBuffer<Level::kTrace>;
using Debug = LogBuffer<Level::kDebug>;
using Info = LogBuffer<Level::kInfo>;
using Warning = LogBuffer<Level::kWarning>;
using Error = LogBuffer<Level::kError>;
using Critical = LogBuffer<Level::kCritical>;
using Message = LogBuffer<Level::kNone>;

}  // namespace silkworm::log

#define SILK_LOGBUFFER(level_)                    \
    if (!silkworm::log::test_verbosity(level_)) { \
    } else                                        \
        silkworm::log::LogBuffer<level_>()

#define SILK_TRACE SILK_LOGBUFFER(silkworm::log::Level::kTrace)
#define SILK_DEBUG SILK_LOGBUFFER(silkworm::log::Level::kDebug)
#define SILK_INFO SILK_LOGBUFFER(silkworm::log::Level::kInfo)
#define SILK_WARN SILK_LOGBUFFER(silkworm::log::Level::kWarning)
#define SILK_ERROR SILK_LOGBUFFER(silkworm::log::Level::kError)
#define SILK_CRIT SILK_LOGBUFFER(silkworm::log::Level::kCritical)
#define SILK_LOG SILK_LOGBUFFER(silkworm::log::Level::kNone)
