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

using namespace silkworm;

void parse_command_line(CLI::App& cli, int argc, char* argv[], log::Settings& log_settings) {
    // Logging options
    auto& log_opts = *cli.add_option_group("Log", "Logging options");
    log_opts.add_option("--log.verbosity", log_settings.log_verbosity, "Sets log verbosity", true)
        ->check(CLI::Range(1u, 6u));
    log_opts.add_flag("--log.stdout", log_settings.log_std_out, "Outputs to std::out instead of std::err");
    log_opts.add_flag("--log.nocolor", log_settings.log_nocolor, "Disable colors on log lines");
    log_opts.add_flag("--log.utc", log_settings.log_utc, "Prints log timings in UTC");
    log_opts.add_flag("--log.threads", log_settings.log_threads, "Prints thread ids");
    log_opts.add_option("--log.file", log_settings.log_file, "Tee all log lines to given file name");

    cli.parse(argc, argv);
}

int main(int argc, char* argv[]) {

    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);

    try {
        log::Settings log_settings{};  // Holds logging settings

        parse_command_line(cli, argc, argv, log_settings);

        log::init(log_settings);  // Initialize logging with cli settings


    } catch (const CLI::ParseError& ex) {
        return cli.exit(ex);
    } catch (const std::exception& ex) {
        std::cerr << "Unexpecter error : " << ex.what() << "\n" << std::endl;
        return -4;
    } catch (...) {
        std::cerr << "\nUnexpected undefined error\n" << std::endl;
        return -99;
    }

    log::CriticalChannel() << "This is a critical message";
    log::ErrorChannel() << "This is a error message";
    log::WarningChannel() << "This is a warning message";
    log::InfoChannel() << "This is a info message";
    log::DebugChannel() << "This is a debug message";
    log::TraceChannel() << "This is a trace message";
    log::set_verbosity(log::Level::None);
    log::TraceChannel() << "This is a trace message";
    log::MessageChannel() << "Simple message";

    return 0;
}
