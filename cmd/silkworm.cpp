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
#include <regex>

#include <CLI/CLI.hpp>
#include <boost/asio/ip/address.hpp>

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

struct PruneModeValidator : public CLI::Validator {
    PruneModeValidator() {
        func_ = [](const std::string& value) -> std::string {
            if (value.find_first_not_of("hrtc") != std::string::npos) {
                return "Value " + value + " contains other characters other than h r t c";
            }
            return {};
        };
    }
};

struct EndPointValidator : public CLI::Validator {
    EndPointValidator() {
        func_ = [](const std::string& value) -> std::string {
            const std::regex pattern(R"(([\da-fA-F\.\:]*)\:([\d]*))");
            std::smatch matches;
            if (!std::regex_match(value, matches, pattern)) {
                return "Value " + value + " is not a valid endpoint";
            }

            // Validate IP address
            boost::system::error_code err;
            std::string ip_address{boost::asio::ip::address::from_string(matches[1], err).to_string()};
            if (err) {
                return "Value " + std::string(matches[1]) + " is not a valid ip address";
            }

            // Validate port
            int port{std::stoi(matches[2])};
            if (port < 1 || port > 65535) {
                return "Value " + std::string(matches[2]) + " is not a valid listening port";
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
    cli.add_option("--prune", node_settings.prune_mode,
                   "Choose which ancient data delete from DB : \n"
                   "h - prune history (ChangeSets, HistoryIndices - used by historical state access)\n"
                   "r - prune receipts (Receipts, Logs, LogTopicIndex, LogAddressIndex - used by eth_getLogs and "
                   "similar RPC methods)\n"
                   "t - prune transaction by it's hash index\n"
                   "c - prune call traces (used by trace_* methods)\n"
                   "Does delete data older than 90K block (can set another value by '--prune.*.older' flags)\n"
                   "If item is NOT in the list - means NO pruning for this data.s\n"
                   "Example: --prune=hrtc (default: none)",
                   true)
        ->check(PruneModeValidator());
    cli.add_option("--chaindata.maxsize", chaindata_max_size, "Max chaindata database size", true)
        ->check(HumanSizeParserValidator("64MB"));
    cli.add_option("--batchsize", batch_size, "Batch size for stage execution", true)
        ->check(HumanSizeParserValidator("64MB", {"1GB"}));
    cli.add_option("--etl.buffersize", etl_buffer_size, "Buffer size for ETL operations", true)
        ->check(HumanSizeParserValidator("64MB", {"1GB"}));
    cli.add_option("--private.api.addr", node_settings.private_api_addr,
                   "Private API network address to serve remote database interface\n"
                   "An empty string means to not start the listener\n"
                   "Use the endpoint form i.e. ip-address:port\n"
                   "DO NOT EXPOSE TO THE INTERNET",
                   true)->check(EndPointValidator());

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
