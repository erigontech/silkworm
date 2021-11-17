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

#include <sstream>
#include <filesystem>

#include <silkworm/common/tee.hpp>

namespace silkworm::log {

// available verbosity levels
enum class LogLevel { Trace, Debug, Info, Warn, Error, Critical, None };

//! \brief Sets logging verbosity
void set_verbosity(LogLevel level);

//! \brief Sets a file path where to tee log messages
void set_tee(std::filesystem::path file);

// change if thread is logged (true) or not (false) - default is false
//
#define SILKWORM_LOG_THREAD(log_thread_) (silkworm::log_thread_enabled_ = (log_thread_))


// change the logging output streams - default is (cerr, null_stream())
//
#define SILKWORM_LOG_STREAMS(stream1_, stream2_) silkworm::log_set_streams_((stream1_), (stream2_));

// silence
std::ostream& null_stream();


void log_set_streams_(std::ostream& o1, std::ostream& o2);

class LogBufferBase {
  public:
    explicit LogBufferBase(LogLevel level);
    ~LogBufferBase() {
        flush();
    }

    // Accumulators
    template <class T>
    inline void append(T const& t) {
        ss_ << t;
    }
    template <class T>
    LogBufferBase& operator<<(T const& t) {
        append(t);
        return *this;
    }

  protected:
    void flush();
    LogLevel level_;
    std::stringstream ss_;
};

template <LogLevel level>
class LogBuffer : public LogBufferBase {
  public:
    LogBuffer() : LogBufferBase(level){};
};

using TraceChannel = LogBuffer<LogLevel::Trace>;
using DebugChannel = LogBuffer<LogLevel::Debug>;
using InfoChannel = LogBuffer<LogLevel::Info>;
using WarningChannel = LogBuffer<LogLevel::Warn>;
using ErrorChannel = LogBuffer<LogLevel::Error>;
using CriticalChannel = LogBuffer<LogLevel::Critical>;
using MessageChannel = LogBuffer<LogLevel::None>;


}  // namespace silkworm::log

#endif  // !SILKWORM_COMMON_LOG_HPP_
