/*
    Copyright 2021 The Silkworm Authors

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

#include <CLI/CLI.hpp>

#include <silkworm/common/log.hpp>

#if defined(_WIN32)
#include <windows.h>
#if !defined(ENABLE_VIRTUAL_TERMINAL_PROCESSING)
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#endif

using namespace silkworm;

struct LogConfig {
    bool log_utc{false};      // Whether timestamps should be in UTC or imbue local timezone
    bool log_nocolor{false};  // Whether to disable colorized output
    uint32_t log_level{4};    // Log verbosity level
};

void init_logging(LogConfig& config) {
    switch (config.log_level) {
        case 1:
            SILKWORM_LOG_VERBOSITY(LogLevel::Critical);
            break;
        case 2:
            SILKWORM_LOG_VERBOSITY(LogLevel::Error);
            break;
        case 3:
            SILKWORM_LOG_VERBOSITY(LogLevel::Warn);
            break;
        case 4:
            SILKWORM_LOG_VERBOSITY(LogLevel::Info);
            break;
        case 5:
            SILKWORM_LOG_VERBOSITY(LogLevel::Debug);
            break;
        case 6:
            SILKWORM_LOG_VERBOSITY(LogLevel::Trace);
            break;
        default:
            /* Should not happen but removes warning about potentially uncovered pattern */
            throw std::invalid_argument("Invalid --log.level");
    }
}

int main(int argc, char* argv[]) {

    LogConfig log_config;

    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);

    // Logging options
    cli.add_option("--log.level", log_config.log_level, "Sets log verbosity", true)->check(CLI::Range(1u, 6u));
    cli.add_flag("--log.nocolor", log_config.log_nocolor, "Disable colors on log lines");
    cli.add_flag("--log.utc", log_config.log_utc, "Prints log timings in UTC");

    CLI11_PARSE(cli, argc, argv);

#if defined(_WIN32)
    // Change code page to UTF-8 so log characters are displayed correctly in console
    // and also support virtual terminal processing for coloring output
    SetConsoleOutputCP(CP_UTF8);
    HANDLE output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output_handle != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(output_handle, &mode)) {
            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(output_handle, mode);
        }
    }
#endif

    init_logging(log_config);

    SILKWORM_LOG(LogLevel::Critical) << "This is a critical message" << std::endl;
    SILKWORM_LOG(LogLevel::Error) << "This is a error message" << std::endl;
    SILKWORM_LOG(LogLevel::Warn) << "This is a warning message" << std::endl;
    SILKWORM_LOG(LogLevel::Info) << "This is a info message" << std::endl;
    SILKWORM_LOG(LogLevel::Debug) << "This is a debug message" << std::endl;
    SILKWORM_LOG(LogLevel::Trace) << "This is a trace message" << std::endl;
    SILKWORM_LOG(LogLevel::None) << "This is a none message" << std::endl;

    return 0;
}
