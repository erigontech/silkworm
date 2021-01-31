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
/*

Usage:

// log to default logger - cerr
SILKWORM_LOG(LogInfo) << "default logger" << endl;

// create local logger and log to it
silkworm::Logger logger(LogInfo, cerr, file_ostream);

SILKWORM_LOG_TO(logger, LogCritical) << "local logger" << endl;

Also, to reset the logging level of default or local logger:

SILKWORM_LOG_VERBOSITY(level);
SILKWORM_LOG_VERBOSITY_OF(logger, level);

*/

#ifndef SILKWORM_COMMON_LOG_H_
#define SILKWORM_COMMON_LOG_H_

#include <silkworm/common/tee.hpp>

namespace silkworm {

enum LogLevels { LogTrace, LogDebug, LogInfo, LogWarn, LogError, LogCritical, LogNone };

// Log to one or two output streams - typically the console and optional log file.
class Logger {
  public:
    explicit Logger(std::ostream& o1 = std::cerr, std::ostream& o2 = Logger::null_stream_()) : stream_(o1, o2) {}

    // public only for access by macros :(
    std::ostream& log_(LogLevels level) {
        return stream_ << kLogTags[level]
                       << "["
                       << formatTime("%m-%d|%H:%M:%E3S")
                       << "] ";
    }
    LogLevels verbosity_{LogInfo};
    bool localTime_{true};  // for compatibility with TG logging, false means UTC
    static Logger& default_logger_() noexcept;

  private:
    teestream stream_;
    std::string formatTime(std::string format) noexcept;
    static std::ostream& null_stream_();
    static constexpr char const kLogTags[7][6] = {
        "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "CRIT ", "NONE ",
    };
};

// Example usage:
// SILKWORM_LOG(LogInfo) << "All your " << num_bases << " base are belong to us\n";
//

#define SILKWORM_LOG_TO(logger_, level_)  \
    if ((level_) < (logger_).verbosity_) {} \
    else (logger_).log_(level_)

#define SILKWORM_LOG(level_) SILKWORM_LOG_TO(Logger::default_logger_(), (level_))

#define SILKWORM_LOG_LOCALTIME_OF(logger_, yes_) ((logger_).localTime_ = (yes_))
#define SILKWORM_LOG_LOCALTIME(yes_) SILKWORM_LOG_LOCALTIME_OF(Logger::default_logger_(), (yes_))

#define SILKWORM_LOG_VERBOSITY_OF(logger_, level_) ((logger_).verbosity_ = (level_))
#define SILKWORM_LOG_VERBOSITY(level_) SILKWORM_LOG_VERBOSITY_OF(Logger::default_logger_(), (level_))

}  // namespace silkworm

#endif  // SILKWORM_COMMON_LOG_H_
