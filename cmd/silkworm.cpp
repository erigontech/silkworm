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

#include <map>
#include <optional>
#include <regex>

#include <CLI/CLI.hpp>
#include <boost/asio/ip/address.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/chain/genesis.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/stages.hpp>

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
    std::string chaindata_max_size{human_size(node_settings.chaindata_config.max_size)};
    std::string chaindata_growth_size{human_size(node_settings.chaindata_config.growth_size)};
    std::string batch_size{human_size(node_settings.batch_size)};
    std::string etl_buffer_size{human_size(node_settings.etl_buffer_size)};
    cli.add_option("--datadir", datadir, "Path to data directory", true);
    cli.add_option("--chaindata.maxsize", chaindata_max_size, "Chaindata database max size", true)
        ->check(HumanSizeParserValidator("64MB", {"4TB"}));
    cli.add_option("--chaindata.growthsize", chaindata_growth_size, "Chaindata database growth size", true)
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
                   true)
        ->check(EndPointValidator());
    cli.add_flag("--fakepow", node_settings.fake_pow, "Disables proof-of-work verification");

    // Chain options
    auto chains_map{get_known_chains_map()};
    auto& chain_opts = *cli.add_option_group("Chain", "Chain selection options");
    auto chain_opts_chain_name = chain_opts.add_option("--chain", "Name of the network to join (default: \"mainnet\")")
                                     ->transform(CLI::Transformer(chains_map, CLI::ignore_case));
    chain_opts
        .add_option("--networkid", node_settings.network_id,
                    "Explicitly set network id\n"
                    "For known networks: use --chain <testnet_name> instead",
                    true)
        ->excludes(chain_opts_chain_name);

    // Prune options
    std::string prune_mode;
    auto& prune_opts = *cli.add_option_group("Prune", "Prune options to delete ancient data from DB");
    prune_opts
        .add_option("--prune", prune_mode,
                    "Delete data older than 90K blocks (see \"--prune.*.older\" for different height)\n"
                    "h - prune history (ChangeSets, HistoryIndices - used by historical state access)\n"
                    "r - prune receipts (Receipts, Logs, LogTopicIndex, LogAddressIndex - used by eth_getLogs and "
                    "similar RPC methods)\n"
                    "t - prune transaction by it's hash index\n"
                    "c - prune call traces (used by trace_* methods)\n"
                    "If item is NOT in the list - means NO pruning for this data.\n"
                    "Example: --prune=hrtc (default: none)",
                    true)
        ->check(PruneModeValidator());

    prune_opts.add_option("--prune.h.older", "Override default 90k blocks of history to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.r.older", "Override default 90k blocks of receipts to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.t.older", "Override default 90k blocks of transactions to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.c.older", "Override default 90k blocks of call traces to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.h.before", "Prune history data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.r.before", "Prune receipts data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.t.before", "Prune transactions data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.c.before", "Prune call traces data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));

    // Logging options
    auto& log_opts = *cli.add_option_group("Log", "Logging options");
    log_opts.add_option("--log.verbosity", log_settings.log_verbosity, "Sets log verbosity", true)
        ->check(CLI::Range(static_cast<uint32_t>(log::Level::kCritical), static_cast<uint32_t>(log::Level::kTrace)))
        ->default_val(std::to_string(static_cast<uint32_t>(log_settings.log_verbosity)));
    log_opts.add_flag("--log.stdout", log_settings.log_std_out, "Outputs to std::out instead of std::err");
    log_opts.add_flag("--log.nocolor", log_settings.log_nocolor, "Disable colors on log lines");
    log_opts.add_flag("--log.utc", log_settings.log_utc, "Prints log timings in UTC");
    log_opts.add_flag("--log.threads", log_settings.log_threads, "Prints thread ids");
    log_opts.add_option("--log.file", log_settings.log_file, "Tee all log lines to given file name");

    cli.parse(argc, argv);

    // Assign settings
    node_settings.data_directory = std::make_unique<DataDirectory>(datadir, /*create=*/true);
    node_settings.chaindata_config.max_size = parse_size(chaindata_max_size).value();
    node_settings.chaindata_config.growth_size = parse_size(chaindata_growth_size).value();
    if (node_settings.chaindata_config.growth_size > node_settings.chaindata_config.max_size / 2) {
        throw std::invalid_argument("--chaindata.growthsize too wide");
    }
    node_settings.batch_size = parse_size(batch_size).value();
    node_settings.etl_buffer_size = parse_size(etl_buffer_size).value();
    node_settings.prune_mode = db::parse_prune_mode(prune_mode);
    if (cli["--prune.h.older"]->count()) node_settings.prune_mode.history = cli["--prune.h.older"]->as<BlockNum>();
    if (cli["--prune.r.older"]->count()) node_settings.prune_mode.receipts = cli["--prune.r.older"]->as<BlockNum>();
    if (cli["--prune.t.older"]->count()) node_settings.prune_mode.tx_index = cli["--prune.t.older"]->as<BlockNum>();
    if (cli["--prune.c.older"]->count()) node_settings.prune_mode.call_traces = cli["--prune.c.older"]->as<BlockNum>();
    // TODO (Andrea) - Prune before

    // Set chain
    if (chain_opts_chain_name->count()) {
        node_settings.network_id = chain_opts_chain_name->as<uint32_t>();
    }
}

int main(int argc, char* argv[]) {
    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);

    try {
        log::Settings log_settings{};  // Holds logging settings
        NodeSettings node_settings{};  // Holds node settings

        parse_command_line(cli, argc, argv, log_settings, node_settings);

        log::init(log_settings);                      // Initialize logging with cli settings
        node_settings.data_directory->etl().clear();  // Clear previous etl files (if any)
        {
            auto& config = node_settings.chaindata_config;
            config.path = node_settings.data_directory->chaindata().path().string();
            config.create =
                !std::filesystem::exists(db::get_datafile_path(node_settings.data_directory->chaindata().path()));
        }

        // Open chaindata environment and check tables are consistent
        log::Message() << "Opening Database chaindata path " << node_settings.data_directory->chaindata().path();
        auto chaindata_env{silkworm::db::open_env(node_settings.chaindata_config)};

        // Deploy and check tables
        {
            auto tx{chaindata_env.start_write()};
            db::table::check_or_create_chaindata_tables(tx);
            tx.commit();
        }

        // Check db is initialized with chain config
        {
            db::RWTxn tx(chaindata_env);
            auto db_chain_config{db::read_chain_config(*tx)};
            while (!db_chain_config.has_value()) {
                auto source_data{read_genesis_data(node_settings.network_id)};
                auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
                if (genesis_json.is_discarded()) {
                    throw std::runtime_error("Could not initialize db for chain id " +
                                             std::to_string(node_settings.network_id) + " : unknown network");
                }
                log::Message() << "Initializing chain configuration for chain id " << node_settings.network_id;
                db::initialize_genesis(*tx, genesis_json, /*allow_exceptions=*/true);
                tx.commit();
                log::Message() << "Initialized chain configuration " << db_chain_config.value().to_json().dump();
                db_chain_config = db::read_chain_config(*tx);
            }

            if (db_chain_config.value().chain_id != node_settings.network_id) {
                throw std::runtime_error("Incompatible network id. Command line expects " +
                                         std::to_string(node_settings.network_id) + "; Database has " +
                                         std::to_string(db_chain_config.value().chain_id));
            }
            std::string chain_name{" unknown/custom network"};
            auto chains_map{get_known_chains_map()};
            for (auto& [name, id] : chains_map) {
                if (id == db_chain_config.value().chain_id) {
                    chain_name = name;
                    break;
                }
            }
            log::Message() << "Starting Silkworm on " << chain_name;
        }

        // Detect prune-mode and verify is compatible
        {
            db::RWTxn tx(chaindata_env);
            auto db_prune_mode{db::read_prune_mode(*tx)};
            if (db_prune_mode != node_settings.prune_mode) {
                // In case we have mismatching modes (cli != db) we prevent
                // further execution ONLY if we've already synced something
                auto header_download_progress{db::stages::read_stage_progress(*tx, db::stages::kHeadersKey)};
                if (header_download_progress) {
                    throw std::runtime_error("Can't change prune_mode on already synced data. Expected " +
                                             node_settings.prune_mode.to_string() + " got " +
                                             db_prune_mode.to_string());
                }
                db::write_prune_mode(*tx, node_settings.prune_mode);
                tx.commit();
                db_prune_mode = db::read_prune_mode(*tx);
            }
            log::Message() << "Prune mode " << db_prune_mode.to_string();
        }

        // Do sync stuff here

        log::Message() << "Closing Database chaindata path " << node_settings.data_directory->chaindata().path();
        chaindata_env.close();

    } catch (const CLI::ParseError& ex) {
        return cli.exit(ex);
    } catch (const std::runtime_error& ex) {
        log::Error() << ex.what();
        return -1;
    } catch (const std::invalid_argument& ex) {
        std::cerr << "\tInvalid argument :" << ex.what() << "\n" << std::endl;
        return -3;
    } catch (const std::exception& ex) {
        std::cerr << "\tUnexpected error : " << ex.what() << "\n" << std::endl;
        return -4;
    } catch (...) {
        std::cerr << "\tUnexpected undefined error\n" << std::endl;
        return -99;
    }

    return 0;
}
