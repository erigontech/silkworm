/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_LOG_H_
#define SILKWORM_COMMON_LOG_H_

#include <absl/time/clock.h>

#include <silkworm/common/tee.hpp>

namespace silkworm {

enum LogLevels { LogTrace, LogDebug, LogInfo, LogWarn, LogError, LogCritical, LogNone };

// Log to one or two output streams - typically the console and optional log file.
class Logger {
  public:
    explicit Logger(std::ostream& o1 = std::cerr, std::ostream& o2 = Logger::null_stream()) : stream_(o1, o2) {}

    LogLevels verbosity{LogInfo};

    void set_local_timezone(bool local) noexcept { timezone_ = local ? absl::LocalTimeZone() : absl::UTCTimeZone(); }

    std::ostream& log(LogLevels level) {
        return stream_ << kLogTags[level] << "[" << absl::FormatTime("%m-%d|%H:%M:%E3S", absl::Now(), timezone_)
                       << "] ";
    }

    static Logger& default_logger() noexcept;
    static std::ostream& null_stream();

  private:
    teestream stream_;
    absl::TimeZone timezone_{absl::UTCTimeZone()};
    static constexpr char const kLogTags[7][6] = {
        "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "CRIT ", "NONE",
    };
};

#define SILKWORM_LOG_TO(logger_, level_)  \
    if ((level_) < (logger_).verbosity) { \
    } else                                \
        (logger_).log((level_))

// Example usage:
// SILKWORM_LOG(LogInfo) << "All your " << num_bases << " base are belong to us\n";
#define SILKWORM_LOG(level_) SILKWORM_LOG_TO(Logger::default_logger(), (level_))

}  // namespace silkworm

#endif  // SILKWORM_COMMON_LOG_H_
