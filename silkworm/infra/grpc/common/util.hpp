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

#include <ostream>
#include <string>

#include <absl/log/log_sink_registry.h>
#include <grpcpp/grpcpp.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/common/log.hpp>

namespace grpc {

// operator== overloading for grpc::Status is *NOT* present in gRPC library
inline bool operator==(const Status& lhs, const Status& rhs) {
    return lhs.error_code() == rhs.error_code() &&
           lhs.error_message() == rhs.error_message() &&
           lhs.error_details() == rhs.error_details();
}

// operator<< overloading for grpc::Status is *NOT* present in gRPC library
inline std::ostream& operator<<(std::ostream& out, const Status& status) {
    out << "status=" << (status.ok() ? "OK" : "KO");
    if (!status.ok()) {
        out << " error_code=" << status.error_code()
            << " error_message=" << status.error_message()
            << " error_details=" << status.error_details();
    }
    return out;
}

}  // namespace grpc

namespace silkworm::log {

inline absl::LogSeverityAtLeast absl_min_log_level_from_silkworm(Level level) {
    switch (level) {
        case Level::kNone:
            return absl::LogSeverityAtLeast::kInfinity;
        case Level::kCritical:
            return absl::LogSeverityAtLeast::kFatal;
        case Level::kError:
            return absl::LogSeverityAtLeast::kError;
        case Level::kWarning:
            return absl::LogSeverityAtLeast::kWarning;
        case Level::kInfo:
        case Level::kDebug:
        case Level::kTrace:
            return absl::LogSeverityAtLeast::kInfo;
    }
    SILKWORM_ASSERT(false);
    return absl::LogSeverityAtLeast::kInfinity;
}

inline int absl_max_vlog_level_from_silkworm(Level level) {
    switch (level) {
        case Level::kNone:
            return -1;
        case Level::kCritical:
        case Level::kError:
        case Level::kWarning:
        case Level::kInfo:
            return 0;
        case Level::kDebug:
            return 2;
        case Level::kTrace:
            return 4;
    }
    SILKWORM_ASSERT(false);
    return -1;
}

inline Level level_from_absl(absl::LogSeverity severity, int verbosity) {
    if (verbosity >= 4)
        return Level::kTrace;
    if (verbosity >= 2)
        return Level::kDebug;
    switch (severity) {
        case absl::LogSeverity::kInfo:
            return Level::kInfo;
        case absl::LogSeverity::kWarning:
            return Level::kWarning;
        case absl::LogSeverity::kError:
            return Level::kError;
        case absl::LogSeverity::kFatal:
            return Level::kCritical;
    }
    return Level::kNone;
}

//! Define a gRPC logging function delegating to Silkworm logging facility.
struct AbseilToSilkwormLogSink : public absl::LogSink {
    ~AbseilToSilkwormLogSink() override = default;
    void Send(const absl::LogEntry& entry) override {
        Level level = level_from_absl(entry.log_severity(), entry.verbosity());
        if (test_verbosity(level)) {
            auto text_message = entry.text_message();
            BufferBase log{level, {text_message.data(), text_message.size()}, {}};
        }
    }
};

struct AbseilToVoidLogSink : public absl::LogSink {
    ~AbseilToVoidLogSink() override = default;
    void Send(const absl::LogEntry&) override {}
};

//! Utility to configure absl::LogSink using RAII for an instance lifetime.
template <class TLogSink>
class AbseilLogGuard {
  public:
    explicit AbseilLogGuard() { absl::AddLogSink(&sink_); }
    ~AbseilLogGuard() { absl::RemoveLogSink(&sink_); }
    const TLogSink& sink() const { return sink_; }

  private:
    TLogSink sink_;
};

}  // namespace silkworm::log
