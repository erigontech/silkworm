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

#include <iomanip>
#include <silkworm/common/tee.hpp>

namespace silkworm {

enum LogLevels { LogTrace, LogDebug, LogInfo, LogWarn, LogError, LogCritical, LogNone };

// Log to one or two output streams - typically the console and optional log file.
class Logger {
  public:
    Logger(LogLevels level = LogInfo, std::ostream& o1 = std::cerr, std::ostream& o2 = Logger::null_stream())
        : stream(o1, o2), verbosity(level) {}

    int level(LogLevels level) { return verbosity = level; }
    int level() { return verbosity; }

    std::ostream& log(LogLevels level) {
        std::time_t time = std::time(nullptr);
        return stream << LogTags[level] << "[" << std::put_time(std::gmtime(&time), "%m-%d|%H:%M:%S") << "] ";
    }

    static Logger& default_logger();
    static std::ostream& null_stream();

  private:
    teestream stream;
    LogLevels verbosity;
    static constexpr char const LogTags[7][6] = {
        "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "CRIT ", "NONE",
    };
};

#define SILKWORM_LOG_TO(logger_, level_) \
    if ((level_) < (logger_).level()) {  \
    } else                               \
        (logger_).log((level_))
#define SILKWORM_LOG_TO_LEVEL(logger_, level_) ((logger_).level(level_))

#define SILKWORM_LOG(level_) SILKWORM_LOG_TO(Logger::default_logger(), (level_))
#define SILKWORM_LOG_LEVEL(level_) SILKWORM_LOG_TO_LEVEL(Logger::default_logger(), (level_))

}  // namespace silkworm

#endif  // SILKWORM_COMMON_LOG_H_
