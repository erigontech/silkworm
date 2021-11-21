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

#ifndef SILKWORM_COMMON_LOG_HPP_
#define SILKWORM_COMMON_LOG_HPP_

#include <filesystem>
#include <sstream>

#include <silkworm/common/terminal.hpp>

namespace silkworm::log {

//! \brief Available verbosity levels
enum class Level {
    None,      // Simple logging line with no severity (eg. build info)
    Critical,  // An error there's no way we can recover from
    Error,     // We encountered an error which we might be able to recover from
    Warn,      // Something happened and user might have the possibility to amend the situation
    Info,      // Info messages on regular operations
    Debug,     // Debug information
    Trace      // Trace calls to functions
};

//! \brief Holds logging configuration
struct Settings {
    bool log_std_out{false};           // Whether console logging goes to std::cout or std::cerr (default)
    bool log_utc{false};               // Whether timestamps should be in UTC or imbue local timezone
    bool log_nocolor{false};           // Whether to disable colorized output
    bool log_threads{false};           // Whether to print thread ids in log lines
    Level log_verbosity{Level::Info};  // Log verbosity level
    std::string log_file;              // Log to file
};

//! \brief Initializes logging facilities
//! \note This function is not thread safe as it's meant to be used at start of process and never called again
void init(Settings& settings);

//! \brief Sets logging verbosity
//! \note This function is not thread safe as it's meant to be used at start of process and never called again
void set_verbosity(Level level);

//! \brief Sets a file output for log teeing
//! \note This function is not thread safe as it's meant to be used at start of process and never called again
void tee_file(std::filesystem::path path);

class BufferBase {
  public:
    explicit BufferBase(Level level);
    ~BufferBase() { flush(); }

    // Accumulators
    template <class T>
    inline void append(T const& t) {
        ss_ << t;
    }
    template <class T>
    BufferBase& operator<<(T const& t) {
        append(t);
        return *this;
    }

  protected:
    void flush();
    Level level_;
    std::stringstream ss_;
};

template <Level level>
class LogBuffer : public BufferBase {
  public:
    LogBuffer() : BufferBase(level){};
};

using TraceChannel = LogBuffer<Level::Trace>;
using DebugChannel = LogBuffer<Level::Debug>;
using InfoChannel = LogBuffer<Level::Info>;
using WarningChannel = LogBuffer<Level::Warn>;
using ErrorChannel = LogBuffer<Level::Error>;
using CriticalChannel = LogBuffer<Level::Critical>;
using MessageChannel = LogBuffer<Level::None>;

}  // namespace silkworm::log

#endif  // !SILKWORM_COMMON_LOG_HPP_
