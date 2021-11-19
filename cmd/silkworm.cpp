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

#include <optional>

#include <CLI/CLI.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/common/util.hpp>

using namespace silkworm;

struct HumanSizeParserValidator : public CLI::Validator {
    template <typename T>
    explicit HumanSizeParserValidator(T min, std::optional<T> max = std::nullopt) {
        std::stringstream out;
        out << " in [" << min << " - " << (max.has_value() ? max.value() : "∞") << "]";
        description(out.str());

        func_ = [min, max](const std::string& value) -> std::string {
            auto parsed_size{parse_size(value)};
            if (!parsed_size.has_value()) {
                return std::string("Value " + value + " is not a parseable size");
            }
            auto min_size{parse_size(min).value()};
            auto max_size{max.has_value() ? parse_size(max.value()).value() : UINT64_MAX};
            if (parsed_size.value() < min_size || parsed_size.value() > max_size) {
                return "Value " + value + " not in range " + min + " to " + (max.has_value() ? max.value() : "∞");
            }
            return {};
        };
    }
};

void parse_command_line(CLI::App& cli, int argc, char* argv[], log::Settings& log_settings,
                        NodeSettings& node_settings) {
    // Node settings
    std::string datadir{DataDirectory::get_default_storage_path().string()};
    std::string chaindata_max_size{human_size(node_settings.chaindata_max_size)};
    std::string batch_size{human_size(node_settings.batch_size)};
    std::string etl_buffer_size{human_size(node_settings.etl_buffer_size)};
    cli.add_option("--datadir", datadir, "Path to data directory", true);
    cli.add_option("--chaindata.maxsize", chaindata_max_size, "Max chaindata database size", true)
        ->check(HumanSizeParserValidator("64MB"));
    cli.add_option("--batchsize", batch_size, "Batch size for stage execution", true)
        ->check(HumanSizeParserValidator("64MB", {"1GB"}));
    cli.add_option("--etl.buffersize", etl_buffer_size, "Buffer size for ETL operations", true)
        ->check(HumanSizeParserValidator("64MB", {"1GB"}));

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

    // Assign settings
    node_settings.chaindata_max_size = parse_size(chaindata_max_size).value();
    node_settings.batch_size = parse_size(batch_size).value();
}

int main(int argc, char* argv[]) {
    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);

    try {
        log::Settings log_settings{};  // Holds logging settings
        NodeSettings node_settings{};  // Holds node settings

        parse_command_line(cli, argc, argv, log_settings, node_settings);

        log::init(log_settings);  // Initialize logging with cli settings

    } catch (const CLI::ParseError& ex) {
        return cli.exit(ex);
    } catch (const std::exception& ex) {
        std::cerr << "Unexpected error : " << ex.what() << "\n" << std::endl;
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
