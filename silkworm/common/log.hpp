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

#include "tee.hpp"


namespace silkworm {

enum LogLevels {
    LogTrace, LogDebug, LogInfo, LogWarn, LogError, LogCrit
};
const char* LogTags[] = {
    "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "CRIT "
};

// Log to two output streams - typically the console and a log file.
class Logger {
public:
    Logger(std::ostream& o1, std::ostream& o2, LogLevels level)
    : stream(o1, o2), verbosity(level) {}

   void set_verbosity(LogLevels level) { verbosity = level; }
   int get_verbosity() { return verbosity; }

   std::ostream& log(LogLevels level, const char* file, int line){
      std::time_t time = std::time(nullptr);
      return stream << LogTags[level] \
                    << std::put_time(std::gmtime(&time), " %Y-%m-%d_%H:%M:%S_%Z|") \
                    << file << ":" << line << "| ";
   }
private:
   teestream stream;
   LogLevels verbosity;
};

// log to whatever logger is in scope
#define SILKWORM_LOG(level_) \
    if (logger.get_verbosity() < (level_)) {} \
    else logger.log(level_, __FILE__, __LINE__)

}
#endif
