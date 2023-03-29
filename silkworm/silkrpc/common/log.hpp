/*
   Copyright 2023 The Silkworm Authors

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

#include <mutex>
#include <string>

#include <absl/strings/string_view.h>

namespace silkworm {

// available verbosity levels
enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
    None
};

// silence
std::ostream& null_stream();

//
// Below are for access via macros ONLY.
// Placing them in detail namespace prevents use of macros in nested namespace
//
extern LogLevel log_verbosity_;
extern bool log_thread_enabled_;
void log_set_streams_(std::ostream& o1, std::ostream& o2);
class log_ {
  public:
    explicit log_(LogLevel level) : level_(level) { log_mtx_.lock(); }
    ~log_() { log_mtx_.unlock(); }

    template <class T>
    std::ostream& operator<<(const T& message) {
        return header(level_) << message;
    }

  private:
    static std::ostream& header(LogLevel);

    LogLevel level_;
    static std::mutex log_mtx_;
};

using Logger [[maybe_unused]] = log_;

bool AbslParseFlag(absl::string_view text, LogLevel* level, std::string* error);
std::string AbslUnparseFlag(LogLevel level);

}  // namespace silkworm

#define LOG(level_)                           \
    if ((level_) < silkworm::log_verbosity_) { \
    } else                                    \
        silkworm::log_(level_) << " "  // NOLINT

#define SILKRPC_TRACE LOG(silkworm::LogLevel::Trace)
#define SILKRPC_DEBUG LOG(silkworm::LogLevel::Debug)
#define SILKRPC_INFO LOG(silkworm::LogLevel::Info)
#define SILKRPC_WARN LOG(silkworm::LogLevel::Warn)
#define SILKRPC_ERROR LOG(silkworm::LogLevel::Error)
#define SILKRPC_CRIT LOG(silkworm::LogLevel::Critical)
#define SILKRPC_LOG LOG(silkworm::LogLevel::None)

#define SILKRPC_LOG_VERBOSITY(level_) (silkworm::log_verbosity_ = (level_))

#define SILKRPC_LOG_THREAD(log_thread_) (silkworm::log_thread_enabled_ = (log_thread_))

#define SILKRPC_LOG_STREAMS(stream1_, stream2_) silkworm::log_set_streams_((stream1_), (stream2_))
