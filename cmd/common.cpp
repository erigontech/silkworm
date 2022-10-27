/*
   Copyright 2022 The Silkworm Authors

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

PruneModeValidator::PruneModeValidator() {
    func_ = [](const std::string& value) -> std::string {
        if (value.find_first_not_of("hrtc") != std::string::npos) {
            return "Value " + value + " contains other characters other than h r t c";
        }
        return {};
    };
}

IPEndPointValidator::IPEndPointValidator(bool allow_empty) {
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
        boost::asio::ip::make_address(matches[1], err).to_string();
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

void add_logging_options(CLI::App& cli, log::Settings& log_settings) {
    std::map<std::string, log::Level> level_mapping{
        {"critical", log::Level::kCritical},
        {"error", log::Level::kError},
        {"warning", log::Level::kWarning},
        {"info", log::Level::kInfo},
        {"debug", log::Level::kDebug},
        {"trace", log::Level::kTrace},
    };
    auto& log_opts = *cli.add_option_group("Log", "Logging options");
    log_opts.add_option("--log.verbosity", log_settings.log_verbosity, "Sets log verbosity")
        ->capture_default_str()
        ->check(CLI::Range(log::Level::kCritical, log::Level::kTrace))
        ->transform(CLI::Transformer(level_mapping, CLI::ignore_case))
        ->default_val(log_settings.log_verbosity);
    log_opts.add_flag("--log.stdout", log_settings.log_std_out, "Outputs to std::out instead of std::err");
    log_opts.add_flag("--log.nocolor", log_settings.log_nocolor, "Disable colors on log lines");
    log_opts.add_flag("--log.utc", log_settings.log_utc, "Prints log timings in UTC");
    log_opts.add_flag("--log.threads", log_settings.log_threads, "Prints thread ids");
    log_opts.add_option("--log.file", log_settings.log_file, "Tee all log lines to given file name");
}

void add_option_chain(CLI::App& cli, uint64_t& network_id) {
    cli.add_option("--chain", network_id, "Name or ID of the network to join (default: \"mainnet\")")
        ->transform(CLI::Transformer(get_known_chains_map(), CLI::ignore_case));
}

void add_option_data_dir(CLI::App& cli, std::filesystem::path& data_dir) {
    cli.add_option("--datadir", data_dir, "The path to the blockchain data directory")
        ->default_val(DataDirectory::get_default_storage_path().string());
}

void add_option_etherbase(CLI::App& cli, std::string& etherbase_address) {
    cli.add_option("--etherbase", etherbase_address, "The coinbase address as hex string")
        ->default_val("");
}

void add_option_db_max_readers(CLI::App& cli, uint32_t& max_readers) {
    cli.add_option("--mdbx.max.readers", max_readers, "The maximum number of MDBX readers")
        ->default_val(silkworm::db::EnvConfig{}.max_readers)
        ->check(CLI::Range(1, 32767));
}

void add_option_private_api_address(CLI::App& cli, std::string& private_api_address) {
    add_option_ip_address(cli, "--private.api.addr", private_api_address,
                          "Private API network address to serve remote database interface\n"
                          "An empty string means to not start the listener\n"
                          "Use the endpoint form i.e. ip-address:port\n"
                          "DO NOT EXPOSE TO THE INTERNET");
}

void add_option_sentry_api_address(CLI::App& cli, std::string& sentry_api_address) {
    add_option_ip_address(cli, "--sentry.api.addr", sentry_api_address, "Sentry api endpoint");
}

void add_option_external_sentry_address(CLI::App& cli, std::string& external_sentry_address) {
    add_option_ip_address(cli, "--sentry.remote.addr", external_sentry_address, "External Sentry endpoint");
}

void add_option_ip_address(CLI::App& cli, const std::string& name, std::string& address, const std::string& description) {
    cli.add_option(name, address, description)
        ->capture_default_str()
        ->check(IPEndPointValidator(/*allow_empty=*/true));
}

void add_option_num_contexts(CLI::App& cli, uint32_t& num_contexts) {
    cli.add_option("--contexts", num_contexts, "The number of execution contexts")
        ->default_val(std::thread::hardware_concurrency() / 2);
}

void add_option_wait_mode(CLI::App& cli, silkworm::rpc::WaitMode& wait_mode) {
    std::map<std::string, silkworm::rpc::WaitMode> wait_mode_mapping{
        {"backoff", silkworm::rpc::WaitMode::backoff},
        {"blocking", silkworm::rpc::WaitMode::blocking},
        {"busy_spin", silkworm::rpc::WaitMode::busy_spin},
        {"sleeping", silkworm::rpc::WaitMode::sleeping},
        {"yielding", silkworm::rpc::WaitMode::yielding},
    };
    cli.add_option("--wait.mode", wait_mode, "The waiting mode for execution loops during idle cycles")
        ->capture_default_str()
        ->check(CLI::Range(silkworm::rpc::WaitMode::backoff, silkworm::rpc::WaitMode::busy_spin))
        ->transform(CLI::Transformer(wait_mode_mapping, CLI::ignore_case))
        ->default_val(silkworm::rpc::WaitMode::blocking);
}

void parse_silkworm_command_line(CLI::App& cli, int argc, char* argv[], SilkwormCoreSettings& settings) {
    using namespace silkworm::cmd;

    auto& node_settings = settings.node_settings;

    // Node settings
    std::filesystem::path data_dir_path;
    std::string chaindata_max_size_str{human_size(node_settings.chaindata_env_config.max_size)};
    std::string chaindata_growth_size_str{human_size(node_settings.chaindata_env_config.growth_size)};
    std::string chaindata_page_size_str{human_size(node_settings.chaindata_env_config.page_size)};
    std::string batch_size_str{human_size(node_settings.batch_size)};
    std::string etl_buffer_size_str{human_size(node_settings.etl_buffer_size)};
    add_option_data_dir(cli, data_dir_path);

    cli.add_flag("--chaindata.exclusive", node_settings.chaindata_env_config.exclusive,
                 "Chaindata database opened in exclusive mode");
    cli.add_flag("--chaindata.readahead", node_settings.chaindata_env_config.read_ahead,
                 "Chaindata database enable readahead");
    cli.add_flag("--chaindata.writemap", node_settings.chaindata_env_config.write_map,
                 "Chaindata database enable writemap");

    cli.add_option("--chaindata.growthsize", chaindata_growth_size_str, "Chaindata database growth size.")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB"));
    cli.add_option("--chaindata.pagesize", chaindata_page_size_str, "Chaindata database page size. A power of 2")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("256B", {"65KB"}));
    cli.add_option("--chaindata.maxsize", chaindata_max_size_str, "Chaindata database max size.")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("32MB", {"128TB"}));

    cli.add_option("--batchsize", batch_size_str, "Batch size for stage execution")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB", {"16GB"}));
    cli.add_option("--etl.buffersize", etl_buffer_size_str, "Buffer size for ETL operations")
        ->capture_default_str()
        ->check(HumanSizeParserValidator("64MB", {"1GB"}));

    add_option_private_api_address(cli, node_settings.private_api_addr);

    // Sentry settings
    add_option_external_sentry_address(cli, node_settings.external_sentry_addr);

    add_option_sentry_api_address(cli, node_settings.sentry_api_addr);

    cli.add_option("--sync.loop.throttle", node_settings.sync_loop_throttle_seconds,
                   "Sets the minimum delay between sync loop starts (in seconds)")
        ->capture_default_str()
        ->check(CLI::Range(1u, 7200u));

    cli.add_option("--sync.loop.log.interval", node_settings.sync_loop_log_interval_seconds,
                   "Sets the interval between sync loop logs (in seconds)")
        ->capture_default_str()
        ->check(CLI::Range(10u, 600u));

    cli.add_flag("--fakepow", node_settings.fake_pow, "Disables proof-of-work verification");

    // Chain options
    add_option_chain(cli, node_settings.network_id);

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

    // Logging options
    auto& log_settings = settings.log_settings;
    add_logging_options(cli, log_settings);

    // RPC server options
    auto& server_settings = settings.server_settings;

    uint32_t num_contexts;
    add_option_num_contexts(cli, num_contexts);

    silkworm::rpc::WaitMode wait_mode;
    add_option_wait_mode(cli, wait_mode);

    cli.parse(argc, argv);

    // Validate and assign settings
    const auto chaindata_page_size{parse_size(chaindata_page_size_str)};
    if (!chaindata_page_size.has_value() || (*chaindata_page_size & (*chaindata_page_size - 1)) != 0) {
        throw std::invalid_argument("--chaindata.pagesize is not a power of 2");
    }
    node_settings.chaindata_env_config.page_size = chaindata_page_size.value();
    const auto mdbx_max_size_hard_limit{chaindata_page_size.value() * db::kMdbx_max_pages};
    const auto chaindata_max_size{parse_size(chaindata_max_size_str)};
    if (chaindata_max_size.value() > mdbx_max_size_hard_limit) {
        throw std::invalid_argument("--chaindata.maxsize exceeds max allowed size by page size i.e" +
                                    human_size(mdbx_max_size_hard_limit));
    }
    const auto chaindata_growth_size{parse_size(chaindata_growth_size_str)};
    if (chaindata_growth_size > (mdbx_max_size_hard_limit / /* two increments ?*/ 2u)) {
        throw std::invalid_argument("--chaindata.growthsize must be <=" + human_size(mdbx_max_size_hard_limit / 2));
    }

    node_settings.data_directory = std::make_unique<DataDirectory>(data_dir_path, /*create=*/true);
    node_settings.chaindata_env_config.max_size = chaindata_max_size.value();
    node_settings.chaindata_env_config.growth_size = chaindata_growth_size.value();

    node_settings.batch_size = parse_size(batch_size_str).value();
    node_settings.etl_buffer_size = parse_size(etl_buffer_size_str).value();

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

    server_settings.set_address_uri(node_settings.private_api_addr);
    server_settings.set_num_contexts(num_contexts);
    server_settings.set_wait_mode(wait_mode);
}

void run_preflight_checklist(NodeSettings& node_settings, bool init_if_empty) {
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
    const auto header_download_progress{db::stages::read_stage_progress(*tx, db::stages::kHeadersKey)};

    // Check db is initialized with chain config
    {
        node_settings.chain_config = db::read_chain_config(*tx);
        if (!node_settings.chain_config.has_value() && init_if_empty) {
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

        const auto known_chain{lookup_known_chain(node_settings.chain_config->chain_id)};
        if (known_chain.has_value() && *(known_chain->second) != *(node_settings.chain_config)) {
            // If loaded config is known we must ensure is up-to-date with hardcoded one
            // Loop all respective JSON members to find discrepancies
            auto known_chain_config_json{known_chain->second->to_json()};
            auto active_chain_config_json{node_settings.chain_config->to_json()};
            bool new_members_added{false};
            bool old_members_changed(false);
            for (auto& [known_key, known_value] : known_chain_config_json.items()) {
                if (!active_chain_config_json.contains(known_key)) {
                    // Is this new key a definition of a new fork block or a bomb delay block ?
                    // If so we need to check its new value must be **beyond** the highest
                    // header processed.

                    const std::regex block_pattern(R"(Block$)", std::regex_constants::icase);
                    if (std::regex_match(known_key, block_pattern)) {
                        // New forkBlock definition (as well as bomb defusing block) must be "activated" to be relevant.
                        // By "activated" we mean it has to have a value > 0. Code should also take into account
                        // different chain_id(s) if special features are embedded from genesis
                        // All our chain configurations inherit from ChainConfig which necessarily needs to be extended
                        // to allow derivative chains to support new fork blocks

                        if (const auto known_value_activation{known_value.get<uint64_t>()};
                            known_value_activation > 0 && known_value_activation <= header_download_progress) {
                            throw std::runtime_error("Can't apply new chain config key " + known_key + "with value " +
                                                     std::to_string(known_value_activation) +
                                                     " as the database has already blocks up to " +
                                                     std::to_string(header_download_progress));
                        }
                    }

                    new_members_added = true;
                    continue;

                } else {
                    const auto active_value{active_chain_config_json[known_key]};
                    if (active_value.type_name() != known_value.type_name()) {
                        throw std::runtime_error("Hard-coded chain config key " + known_key + " has type " +
                                                 std::string(known_value.type_name()) +
                                                 " whilst persisted config has type " +
                                                 std::string(active_value.type_name()));
                    }

                    if (known_value.is_number()) {
                        // Check whether activation value has been modified
                        const auto known_value_activation{known_value.get<uint64_t>()};
                        const auto active_value_activation{active_value.get<uint64_t>()};
                        if (known_value_activation != active_value_activation) {
                            bool must_throw{false};
                            if (!known_value_activation && active_value_activation &&
                                active_value_activation <= header_download_progress) {
                                // Can't de-activate an already activated fork block
                                must_throw = true;
                            } else if (!active_value_activation && known_value_activation &&
                                       known_value_activation <= header_download_progress) {
                                // Can't activate a fork block BEFORE current height
                                must_throw = true;
                            } else if (known_value_activation && active_value_activation &&
                                       std::min(known_value_activation, active_value_activation) <=
                                           header_download_progress) {
                                // Can change activation height BEFORE current height
                                must_throw = true;
                            }
                            if (must_throw) {
                                throw std::runtime_error("Can't apply modified chain config key " +
                                                         known_key + " from " +
                                                         std::to_string(active_value_activation) + " to " +
                                                         std::to_string(known_value_activation) +
                                                         " as the database has already headers up to " +
                                                         std::to_string(header_download_progress));
                            }
                            old_members_changed = true;
                        }
                    }
                }
            }

            if (new_members_added || old_members_changed) {
                db::update_chain_config(*tx, *(known_chain->second));
                tx.commit();
                node_settings.chain_config = *(known_chain->second);
            }
        }

        // Load genesis_hash
        node_settings.chain_config->genesis_hash = db::read_canonical_header_hash(tx, 0);
        if (!node_settings.chain_config->genesis_hash.has_value())
            throw std::runtime_error("Could not load genesis hash");

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
                                         db_prune_mode.to_string() + " got " + node_settings.prune_mode->to_string());
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

std::string get_node_name_from_build_info(const buildinfo* build_info) {
    std::string node_name{"silkworm/"};
    node_name.append(build_info->git_branch);
    node_name.append(build_info->project_version);
    node_name.append("/");
    node_name.append(build_info->system_name);
    node_name.append("-");
    node_name.append(build_info->system_processor);
    node_name.append("_");
    node_name.append(build_info->build_type);
    node_name.append("/");
    node_name.append(build_info->compiler_id);
    node_name.append("-");
    node_name.append(build_info->compiler_version);
    return node_name;
}

}  // namespace silkworm::cmd
