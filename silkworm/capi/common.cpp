/*
   Copyright 2024 The Silkworm Authors

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

#include "common.hpp"

#include <cstring>

namespace log = silkworm::log;

//! Build Silkworm log level from its C representation
static log::Level make_log_level(const SilkwormLogLevel c_log_level) {
    log::Level verbosity{};
    switch (c_log_level) {
        case SilkwormLogLevel::NONE:
            verbosity = log::Level::kNone;
            break;
        case SilkwormLogLevel::CRITICAL:
            verbosity = log::Level::kCritical;
            break;
        case SilkwormLogLevel::ERROR:
            verbosity = log::Level::kError;
            break;
        case SilkwormLogLevel::WARNING:
            verbosity = log::Level::kWarning;
            break;
        case SilkwormLogLevel::INFO:
            verbosity = log::Level::kInfo;
            break;
        case SilkwormLogLevel::DEBUG:
            verbosity = log::Level::kDebug;
            break;
        case SilkwormLogLevel::TRACE:
            verbosity = log::Level::kTrace;
            break;
    }
    return verbosity;
}

std::filesystem::path parse_path(const char data_dir_path[SILKWORM_PATH_SIZE]) {
    // Treat as char8_t so that filesystem::path assumes UTF-8 encoding of the input path
    auto begin = reinterpret_cast<const char8_t*>(data_dir_path);
    size_t len = strnlen(data_dir_path, SILKWORM_PATH_SIZE);
    return std::filesystem::path{begin, begin + len};
}

log::Settings make_log_settings(const SilkwormLogLevel c_log_level) {
    return {
        .log_utc = false,       // display local time
        .log_timezone = false,  // no timezone ID
        .log_trim = true,       // compact rendering (i.e. no whitespaces)
        .log_verbosity = make_log_level(c_log_level),
    };
}
