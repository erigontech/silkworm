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

#pragma once

#include <mutex>
#include <string>

#include <absl/strings/string_view.h>

namespace silkrpc {

// available verbosity levels
enum class LogLevel { Trace, Debug, Info, Warn, Error, Critical, None };

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
    std::ostream& header_(LogLevel);
    template <class T>
    std::ostream& operator<<(const T& message) {
        return header_(level_) << message;
    }

  private:
    LogLevel level_;
    static std::mutex log_mtx_;
};

using Logger = log_;

bool AbslParseFlag(absl::string_view text, LogLevel* level, std::string* error);
std::string AbslUnparseFlag(LogLevel level);

} // namespace silkrpc

#define LOG(level_) if ((level_) < silkrpc::log_verbosity_) {} else silkrpc::log_(level_) << " " // NOLINT

#define SILKRPC_TRACE LOG(silkrpc::LogLevel::Trace)
#define SILKRPC_DEBUG LOG(silkrpc::LogLevel::Debug)
#define SILKRPC_INFO  LOG(silkrpc::LogLevel::Info)
#define SILKRPC_WARN  LOG(silkrpc::LogLevel::Warn)
#define SILKRPC_ERROR LOG(silkrpc::LogLevel::Error)
#define SILKRPC_CRIT  LOG(silkrpc::LogLevel::Critical)
#define SILKRPC_LOG   LOG(silkrpc::LogLevel::None)

#define SILKRPC_LOG_VERBOSITY(level_) (silkrpc::log_verbosity_ = (level_))

#define SILKRPC_LOG_THREAD(log_thread_) (silkrpc::log_thread_enabled_ = (log_thread_))

#define SILKRPC_LOG_STREAMS(stream1_, stream2_) silkrpc::log_set_streams_((stream1_), (stream2_))

