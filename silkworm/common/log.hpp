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

#include <silkworm/common/tee.hpp>

#include <iomanip>

namespace silkworm {

enum LogLevels {
    LogTrace, LogDebug, LogInfo, LogWarn, LogError, LogCrit, LogNone
};

// Log to two output streams - typically the console and a log file.
class Logger {
public:
    Logger(std::ostream& o1, std::ostream& o2, LogLevels level=LogNone)
    : stream(o1, o2), verbosity(level) {}

    int level(LogLevels level) { return verbosity = level; }
    int level() { return verbosity; }

    std::ostream& log(LogLevels level, const char* file, int line){
    std::time_t time = std::time(nullptr);
    return stream << LogTags[level] \
                  << std::put_time(std::gmtime(&time), " %Y-%m-%d %H:%M:%S %Z ") \
                  << file << ":" << line << "| ";
    }
private:
    teestream stream;
    LogLevels verbosity;
    static constexpr char const LogTags[7][6] = { "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "CRIT ", "NONE" };
};

// log to whatever logger is in scope
#define SILKWORM_LOG(level_) \
    if (logger.level() < (level_)) {} \
    else logger.log(level_, __FILE__, __LINE__)

}
#endif
