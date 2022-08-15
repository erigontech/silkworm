/*
    Copyright 2021-2022 The Silkworm Authors

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

#include <regex>

#include <boost/asio/ip/address.hpp>

#include <silkworm/chain/genesis.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/stages.hpp>

namespace silkworm::cmd {

struct HumanSizeParserValidator : public CLI::Validator {
    template <typename T>
    explicit HumanSizeParserValidator(T min, std::optional<T> max = std::nullopt) {
        std::stringstream out;
        out << " in [" << min << " - " << (max.has_value() ? max.value() : "inf") << "]";
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

IPEndPointValidator::IPEndPointValidator(bool allow_empty) {
    {
        func_ = [&allow_empty](const std::string& value) -> std::string {
            if (value.empty() && allow_empty) {
                return {};
            }

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
}

void add_logging_options(CLI::App& cli, log::Settings& log_settings) {
    auto& log_opts = *cli.add_option_group("Log", "Logging options");
    log_opts.add_option("--log.verbosity", log_settings.log_verbosity, "Sets log verbosity")
        ->capture_default_str()
        ->check(CLI::Range(static_cast<uint32_t>(log::Level::kCritical), static_cast<uint32_t>(log::Level::kTrace)))
        ->default_val(std::to_string(static_cast<uint32_t>(log_settings.log_verbosity)));
    log_opts.add_flag("--log.stdout", log_settings.log_std_out, "Outputs to std::out instead of std::err");
    log_opts.add_flag("--log.nocolor", log_settings.log_nocolor, "Disable colors on log lines");
    log_opts.add_flag("--log.utc", log_settings.log_utc, "Prints log timings in UTC");
    log_opts.add_flag("--log.threads", log_settings.log_threads, "Prints thread ids");
    log_opts.add_option("--log.file", log_settings.log_file, "Tee all log lines to given file name");
}

void add_option_data_dir(CLI::App& cli, std::filesystem::path& data_dir) {
    data_dir = DataDirectory::get_default_storage_path();
    cli.add_option("--datadir", data_dir, "Path to the data directory")->capture_default_str();
}

void add_option_num_contexts(CLI::App& cli, uint32_t& num_contexts) {
    cli.add_option("--contexts", num_contexts, "The number of running contexts")->capture_default_str();
}

void add_option_wait_mode(CLI::App& cli, silkworm::rpc::WaitMode& wait_mode) {
    cli.add_option("--wait.mode", wait_mode, "The waiting mode for execution loops during idle cycles")
        ->capture_default_str()
        ->check(CLI::Range(static_cast<uint32_t>(silkworm::rpc::WaitMode::blocking),
                           static_cast<uint32_t>(silkworm::rpc::WaitMode::busy_spin)))
        ->default_val(std::to_string(static_cast<uint32_t>(silkworm::rpc::WaitMode::blocking)));
}

void parse_silkworm_command_line(CLI::App& cli, int argc, char* argv[], log::Settings& log_settings,
                                 NodeSettings& node_settings) {
    // Node settings
    std::filesystem::path data_dir_path;
    std::string chaindata_max_size{human_size(node_settings.chaindata_env_config.max_size)};
    std::string chaindata_growth_size{human_size(node_settings.chaindata_env_config.growth_size)};
    std::string batch_size{human_size(node_settings.batch_size)};
    std::string etl_buffer_size{human_size(node_settings.etl_buffer_size)};
    add_option_data_dir(cli, data_dir_path);
    cli.add_flag("--chaindata.exclusive", node_settings.chaindata_env_config.exclusive,
                 "Chaindata database opened in exclusive mode");
    cli.add_flag("--chaindata.readahead", node_settings.chaindata_env_config.read_ahead,
                 "Chaindata database enable readahead");
    cli.add_flag("--chaindata.writemap", node_settings.chaindata_env_config.write_map,
                 "Chaindata database enable writemap");
    cli.add_option("--chaindata.growthsize", chaindata_growth_size, "Chaindata database growth size")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB"));
    cli.add_option("--chaindata.maxsize", chaindata_max_size, "Chaindata database max size")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB", {"4TB"}));
    cli.add_option("--batchsize", batch_size, "Batch size for stage execution")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB", {"16GB"}));
    cli.add_option("--etl.buffersize", etl_buffer_size, "Buffer size for ETL operations")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB", {"1GB"}));
    cli.add_option("--private.api.addr", node_settings.private_api_addr,
                   "Private API network address to serve remote database interface\n"
                   "An empty string means to not start the listener\n"
                   "Use the endpoint form i.e. ip-address:port\n"
                   "DO NOT EXPOSE TO THE INTERNET")
        ->capture_default_str()
        ->check(IPEndPointValidator(/*allow_empty=*/false));

    cli.add_option("--sentry.api.addr", node_settings.sentry_api_addr, "Sentry api endpoint")
        ->capture_default_str()
        ->check(IPEndPointValidator(/*allow_empty=*/true));

    cli.add_option("--sync.loop.throttle", node_settings.sync_loop_throttle_seconds,
                   "Sets the minimum time between sync loop starts (in seconds)")
        ->capture_default_str();

    cli.add_option("--sync.loop.log.interval", node_settings.sync_loop_log_interval_seconds,
                   "Sets the minimum time between sync loop logs (in seconds)")
        ->capture_default_str()
        ->check(CLI::Range(5u, 600u));

    cli.add_flag("--fakepow", node_settings.fake_pow, "Disables proof-of-work verification");
    // Chain options
    auto chains_map{get_known_chains_map()};
    auto& chain_opts = *cli.add_option_group("Chain", "Chain selection options");
    auto chain_opts_chain_name = chain_opts.add_option("--chain", "Name of the network to join (default: \"mainnet\")")
                                     ->transform(CLI::Transformer(chains_map, CLI::ignore_case));
    chain_opts
        .add_option("--networkid", node_settings.network_id,
                    "Explicitly set network id\n"
                    "For known networks: use --chain <testnet_name> instead")
        ->capture_default_str()
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
                    "s - prune senders recovered\n"
                    "t - prune transaction by it's hash index\n"
                    "c - prune call traces (used by trace_* methods)\n"
                    "If item is NOT in the list - means NO pruning for this data.\n"
                    "Example: --prune=hrtc (default: none)")
        ->capture_default_str()
        ->check(PruneModeValidator());

    prune_opts.add_option("--prune.h.older", "Override default 90k blocks of history to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.r.older", "Override default 90k blocks of receipts to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.s.older", "Override default 90k blocks of senders to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.t.older", "Override default 90k blocks of transactions to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.c.older", "Override default 90k blocks of call traces to prune")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.h.before", "Prune history data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.r.before", "Prune receipts data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.s.before", "Prune senders data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.t.before", "Prune transactions data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));
    prune_opts.add_option("--prune.c.before", "Prune call traces data before this block")
        ->check(CLI::Range(0u, UINT32_MAX));

    add_logging_options(cli, log_settings);

    cli.parse(argc, argv);

    // Assign settings
    node_settings.data_directory = std::make_unique<DataDirectory>(data_dir_path, /*create=*/true);
    node_settings.chaindata_env_config.max_size = parse_size(chaindata_max_size).value();
    node_settings.chaindata_env_config.growth_size = parse_size(chaindata_growth_size).value();
    if (node_settings.chaindata_env_config.growth_size > node_settings.chaindata_env_config.max_size / 2) {
        throw std::invalid_argument("--chaindata.growthsize too wide");
    }

    node_settings.batch_size = parse_size(batch_size).value();
    node_settings.etl_buffer_size = parse_size(etl_buffer_size).value();

    // Parse prune mode
    db::PruneDistance olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces;
    if (cli["--prune.h.older"]->count()) olderHistory.emplace(cli["--prune.h.older"]->as<BlockNum>());
    if (cli["--prune.r.older"]->count()) olderReceipts.emplace(cli["--prune.r.older"]->as<BlockNum>());
    if (cli["--prune.s.older"]->count()) olderSenders.emplace(cli["--prune.s.older"]->as<BlockNum>());
    if (cli["--prune.t.older"]->count()) olderTxIndex.emplace(cli["--prune.t.older"]->as<BlockNum>());
    if (cli["--prune.c.older"]->count()) olderCallTraces.emplace(cli["--prune.c.older"]->as<BlockNum>());

    db::PruneThreshold beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces;
    if (cli["--prune.h.before"]->count()) beforeHistory.emplace(cli["--prune.h.before"]->as<BlockNum>());
    if (cli["--prune.r.before"]->count()) beforeReceipts.emplace(cli["--prune.r.before"]->as<BlockNum>());
    if (cli["--prune.s.before"]->count()) beforeSenders.emplace(cli["--prune.s.before"]->as<BlockNum>());
    if (cli["--prune.t.before"]->count()) beforeTxIndex.emplace(cli["--prune.t.before"]->as<BlockNum>());
    if (cli["--prune.c.before"]->count()) beforeCallTraces.emplace(cli["--prune.c.before"]->as<BlockNum>());

    node_settings.prune_mode =
        db::parse_prune_mode(prune_mode,  //
                             olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces, beforeHistory,
                             beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces);

    // Set chain
    if (chain_opts_chain_name->count()) {
        node_settings.network_id = chain_opts_chain_name->as<uint32_t>();
    }
}

void run_preflight_checklist(NodeSettings& node_settings) {
    node_settings.data_directory->deploy();                                  // Ensures all subdirs are present
    bool chaindata_exclusive{node_settings.chaindata_env_config.exclusive};  // Save setting
    {
        auto& config = node_settings.chaindata_env_config;
        config.path = node_settings.data_directory->chaindata().path().string();
        config.create =
            !std::filesystem::exists(db::get_datafile_path(node_settings.data_directory->chaindata().path()));
        config.exclusive = true;  // Will be cleared after this phase
    }

    // Open chaindata environment and check tables are consistent
    log::Message("Opening database", {"path", node_settings.data_directory->chaindata().path().string()});
    auto chaindata_env{silkworm::db::open_env(node_settings.chaindata_env_config)};
    db::RWTxn tx(chaindata_env);

    // Ensures all tables are present
    db::table::check_or_create_chaindata_tables(*tx);
    log::Message("Database schema", {"version", db::read_schema_version(*tx)->to_string()});

    // Detect the highest downloaded header. We need that to detect if we can apply changes in chain config and/or
    // prune mode
    auto header_download_progress{db::stages::read_stage_progress(*tx, db::stages::kHeadersKey)};

    // Check db is initialized with chain config
    {
        node_settings.chain_config = db::read_chain_config(*tx);
        if (!node_settings.chain_config.has_value()) {
            auto source_data{read_genesis_data(node_settings.network_id)};
            auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
            if (genesis_json.is_discarded()) {
                throw std::runtime_error("Could not initialize db for chain id " +
                                         std::to_string(node_settings.network_id) + " : unknown network");
            }
            log::Message("Priming database", {"network id", std::to_string(node_settings.network_id)});
            db::initialize_genesis(*tx, genesis_json, /*allow_exceptions=*/true);
            tx.commit();
            node_settings.chain_config = db::read_chain_config(*tx);
        }

        if (!node_settings.chain_config.has_value()) {
            throw std::runtime_error("Unable to retrieve chain configuration");
        } else if (node_settings.chain_config.value().chain_id != node_settings.network_id) {
            throw std::runtime_error("Incompatible network id. Command line expects " +
                                     std::to_string(node_settings.network_id) + "; Database has " +
                                     std::to_string(node_settings.chain_config.value().chain_id));
        }

        auto known_chain{lookup_known_chain(node_settings.chain_config->chain_id)};
        if (known_chain.has_value() && *(known_chain->second) != *(node_settings.chain_config)) {
            // If loaded config is known we must ensure is up-to-date with hardcoded one
            // Loop all respective JSON members to find discrepancies
            auto known_chain_config_json{known_chain->second->to_json()};
            auto active_chain_config_json{node_settings.chain_config->to_json()};
            bool new_members_added{false};
            for (auto& [known_key, known_value] : known_chain_config_json.items()) {
                if (!active_chain_config_json.contains(known_key)) {
                    // Is this new key a definition of a new fork block or a bomb delay block ?
                    // If so we need to check its new value must be **beyond** the highest
                    // header processed.

                    const std::regex block_pattern(R"(Block$)", std::regex_constants::icase);
                    if (std::regex_match(known_key, block_pattern)) {
                        if (known_value.get<uint64_t>() <= header_download_progress) {
                            throw std::runtime_error("Can't apply new chain config key " + known_key + "with value " +
                                                     known_value.get<std::string>() +
                                                     " as the database has already a higher header");
                        }
                    }

                    new_members_added = true;
                    continue;
                }

                auto active_value{active_chain_config_json[known_key]};
                if (active_value.type_name() != known_value.type_name() || active_value != known_value) {
                    throw std::runtime_error(
                        "Hard-coded chain config has incompatible data types or values with stored chain config");
                }
            }

            if (new_members_added) {
                db::update_chain_config(*tx, *(known_chain->second));
                tx.commit();
                node_settings.chain_config = db::read_chain_config(*tx);
            }
        }

        log::Message("Starting Silkworm", {"chain", (known_chain.has_value() ? known_chain->first : "unknown/custom"),
                                           "config", node_settings.chain_config->to_json().dump()});
    }

    // Detect prune-mode and verify is compatible
    {
        auto db_prune_mode{db::read_prune_mode(*tx)};
        if (db_prune_mode != *node_settings.prune_mode) {
            // In case we have mismatching modes (cli != db) we prevent
            // further execution ONLY if we've already synced something
            if (header_download_progress) {
                throw std::runtime_error("Can't change prune_mode on already synced data. Expected " +
                                         node_settings.prune_mode->to_string() + " got " + db_prune_mode.to_string());
            }
            db::write_prune_mode(*tx, *node_settings.prune_mode);
            node_settings.prune_mode = std::make_unique<db::PruneMode>(db::read_prune_mode(*tx));
        }
        log::Message("Effective pruning", {"mode", node_settings.prune_mode->to_string()});
    }

    tx.commit(/*renew=*/false);
    chaindata_env.close();
    node_settings.chaindata_env_config.exclusive = chaindata_exclusive;
    node_settings.chaindata_env_config.create = false;  // Has already been created
}

}  // namespace silkworm::cmd
