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

#include <memory>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <CLI/CLI.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/buildinfo.h>
#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/mem_usage.hpp>
#include <silkworm/infra/common/os.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/async_thread.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/infra/grpc/server/server_context_pool.hpp>
#include <silkworm/node/backend/ethereum_backend.hpp>
#include <silkworm/node/backend/remote/backend_kv_server.hpp>
#include <silkworm/node/common/settings.hpp>
#include <silkworm/node/db/eth_status_data_provider.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/snapshot/sync.hpp>
#include <silkworm/node/stagedsync/local_client.hpp>
#include <silkworm/node/stagedsync/server.hpp>
#include <silkworm/sentry/api/api_common/sentry_client.hpp>
#include <silkworm/sentry/grpc/client/sentry_client.hpp>
#include <silkworm/sentry/multi_sentry_client.hpp>
#include <silkworm/sentry/sentry.hpp>
#include <silkworm/sentry/session_sentry_client.hpp>
#include <silkworm/sentry/settings.hpp>
#include <silkworm/sync/sync.hpp>

#include "common/common.hpp"
#include "common/human_size_parser_validator.hpp"
#include "common/sentry_options.hpp"
#include "common/settings.hpp"
#include "common/shutdown_signal.hpp"
#include "common/snapshot_options.hpp"

namespace sw_db = silkworm::db;
namespace sw_log = silkworm::log;

using namespace silkworm;

using silkworm::ActiveComponent;
using silkworm::BlockExchange;
using silkworm::BlockNum;
using silkworm::DataDirectory;
using silkworm::human_size;
using silkworm::lookup_known_chain;
using silkworm::NodeSettings;
using silkworm::parse_size;
using silkworm::PreverifiedHashes;
using silkworm::read_genesis_data;
using silkworm::StopWatch;
using silkworm::cmd::common::add_context_pool_options;
using silkworm::cmd::common::add_logging_options;
using silkworm::cmd::common::add_option_chain;
using silkworm::cmd::common::add_option_data_dir;
using silkworm::cmd::common::add_option_private_api_address;
using silkworm::cmd::common::add_option_remote_sentry_addresses;
using silkworm::cmd::common::add_sentry_options;
using silkworm::cmd::common::add_snapshot_options;
using silkworm::cmd::common::get_node_name_from_build_info;
using silkworm::cmd::common::HumanSizeParserValidator;
using silkworm::cmd::common::ShutdownSignal;
using silkworm::cmd::common::SilkwormSettings;
using silkworm::snapshot::SnapshotSync;

// progress log
class ResourceUsageLog : public ActiveComponent {
    NodeSettings& node_settings_;

  public:
    explicit ResourceUsageLog(NodeSettings& settings) : node_settings_{settings} {}

    void execution_loop() override {  // todo: this is only a trick, instead use asio timers
        using namespace std::chrono;
        sw_log::set_thread_name("progress-log  ");
        auto start_time = steady_clock::now();
        auto last_update = start_time;
        while (!is_stopping()) {
            std::this_thread::sleep_for(500ms);

            auto now = steady_clock::now();
            if (now - last_update > 300s) {
                sw_log::Info("Resource usage",
                             {"mem", human_size(get_mem_usage()),
                              "chain", human_size(node_settings_.data_directory->chaindata().size()),
                              "etl-tmp", human_size(node_settings_.data_directory->etl().size()),
                              "uptime", StopWatch::format(now - start_time)});
                last_update = now;
            }
        }
    }
};

struct PruneModeValidator : public CLI::Validator {
    explicit PruneModeValidator() {
        func_ = [](const std::string& value) -> std::string {
            if (value.find_first_not_of("hrtc") != std::string::npos) {
                return "Value " + value + " contains other characters other than h r t c";
            }
            return {};
        };
    }
};

void parse_silkworm_command_line(CLI::App& cli, int argc, char* argv[], SilkwormSettings& settings) {
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
    add_option_remote_sentry_addresses(cli, node_settings.remote_sentry_addresses, /* is_required = */ false);
    add_sentry_options(cli, settings.sentry_settings);

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
    add_logging_options(cli, settings.log_settings);

    // RPC server options
    auto& server_settings = settings.server_settings;

    silkworm::concurrency::ContextPoolSettings context_pool_settings;
    add_context_pool_options(cli, context_pool_settings);

    // Snapshot&Bittorrent options
    auto& snapshot_settings = settings.snapshot_settings;
    add_snapshot_options(cli, snapshot_settings);

    cli.parse(argc, argv);

    // Validate and assign settings
    const auto chaindata_page_size{parse_size(chaindata_page_size_str)};
    if (!chaindata_page_size.has_value() || (*chaindata_page_size & (*chaindata_page_size - 1)) != 0) {
        throw std::invalid_argument("--chaindata.pagesize is not a power of 2");
    }
    node_settings.chaindata_env_config.page_size = chaindata_page_size.value();
    const auto mdbx_max_size_hard_limit{chaindata_page_size.value() * sw_db::kMdbxMaxPages};
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
    sw_db::PruneDistance olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces;
    if (cli["--prune.h.older"]->count()) olderHistory.emplace(cli["--prune.h.older"]->as<BlockNum>());
    if (cli["--prune.r.older"]->count()) olderReceipts.emplace(cli["--prune.r.older"]->as<BlockNum>());
    if (cli["--prune.s.older"]->count()) olderSenders.emplace(cli["--prune.s.older"]->as<BlockNum>());
    if (cli["--prune.t.older"]->count()) olderTxIndex.emplace(cli["--prune.t.older"]->as<BlockNum>());
    if (cli["--prune.c.older"]->count()) olderCallTraces.emplace(cli["--prune.c.older"]->as<BlockNum>());

    sw_db::PruneThreshold beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces;
    if (cli["--prune.h.before"]->count()) beforeHistory.emplace(cli["--prune.h.before"]->as<BlockNum>());
    if (cli["--prune.r.before"]->count()) beforeReceipts.emplace(cli["--prune.r.before"]->as<BlockNum>());
    if (cli["--prune.s.before"]->count()) beforeSenders.emplace(cli["--prune.s.before"]->as<BlockNum>());
    if (cli["--prune.t.before"]->count()) beforeTxIndex.emplace(cli["--prune.t.before"]->as<BlockNum>());
    if (cli["--prune.c.before"]->count()) beforeCallTraces.emplace(cli["--prune.c.before"]->as<BlockNum>());

    node_settings.prune_mode =
        sw_db::parse_prune_mode(prune_mode,  //
                                olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces, beforeHistory,
                                beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces);

    server_settings.set_address_uri(node_settings.private_api_addr);
    server_settings.set_context_pool_settings(context_pool_settings);

    snapshot_settings.bittorrent_settings.repository_path = snapshot_settings.repository_dir;
}

//! Raise allowed max file descriptors in the current process
void raise_max_file_descriptors() {
    constexpr uint64_t kMaxFileDescriptors{10'240};

    const bool set_fd_result = silkworm::os::set_max_file_descriptors(kMaxFileDescriptors);
    if (!set_fd_result) {
        throw std::runtime_error{"Cannot increase max file descriptor up to " + std::to_string(kMaxFileDescriptors)};
    }
}

//! \brief Ensure database is ready to take off and consistent with command line arguments
void run_preflight_checklist(NodeSettings& node_settings, bool init_if_empty = true) {
    node_settings.data_directory->deploy();                                  // Ensures all subdirs are present
    bool chaindata_exclusive{node_settings.chaindata_env_config.exclusive};  // Save setting
    {
        auto& config = node_settings.chaindata_env_config;
        config.path = node_settings.data_directory->chaindata().path().string();
        config.create =
            !std::filesystem::exists(sw_db::get_datafile_path(node_settings.data_directory->chaindata().path()));
        config.exclusive = true;  // Will be cleared after this phase
    }

    // Open chaindata environment and check tables are consistent
    sw_log::Message("Opening database", {"path", node_settings.data_directory->chaindata().path().string()});
    auto chaindata_env{sw_db::open_env(node_settings.chaindata_env_config)};
    sw_db::RWTxn tx(chaindata_env);

    // Ensures all tables are present
    sw_db::table::check_or_create_chaindata_tables(tx);
    sw_log::Message("Database schema", {"version", sw_db::read_schema_version(tx)->to_string()});

    // Detect the highest downloaded header. We need that to detect if we can apply changes in chain config and/or
    // prune mode
    const auto header_download_progress{sw_db::stages::read_stage_progress(tx, sw_db::stages::kHeadersKey)};

    // Check db is initialized with chain config
    {
        node_settings.chain_config = sw_db::read_chain_config(tx);
        if (!node_settings.chain_config.has_value() && init_if_empty) {
            auto source_data{read_genesis_data(node_settings.network_id)};
            auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
            if (genesis_json.is_discarded()) {
                throw std::runtime_error("Could not initialize db for chain id " +
                                         std::to_string(node_settings.network_id) + " : unknown network");
            }
            sw_log::Message("Priming database", {"network id", std::to_string(node_settings.network_id)});
            sw_db::initialize_genesis(tx, genesis_json, /*allow_exceptions=*/true);
            tx.commit();
            node_settings.chain_config = sw_db::read_chain_config(tx);
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
                sw_db::update_chain_config(tx, *(known_chain->second));
                tx.commit();
                node_settings.chain_config = *(known_chain->second);
            }
        }

        // Load genesis_hash
        node_settings.chain_config->genesis_hash = sw_db::read_canonical_header_hash(tx, 0);
        if (!node_settings.chain_config->genesis_hash.has_value())
            throw std::runtime_error("Could not load genesis hash");

        sw_log::Message("Starting Silkworm", {"chain", (known_chain.has_value() ? known_chain->first : "unknown/custom"),
                                              "config", node_settings.chain_config->to_json().dump()});
    }

    // Detect prune-mode and verify is compatible
    {
        auto db_prune_mode{sw_db::read_prune_mode(*tx)};
        if (db_prune_mode != *node_settings.prune_mode) {
            // In case we have mismatching modes (cli != db) we prevent
            // further execution ONLY if we've already synced something
            if (header_download_progress) {
                throw std::runtime_error("Can't change prune_mode on already synced data. Expected " +
                                         db_prune_mode.to_string() + " got " + node_settings.prune_mode->to_string());
            }
            sw_db::write_prune_mode(*tx, *node_settings.prune_mode);
            node_settings.prune_mode = std::make_unique<sw_db::PruneMode>(sw_db::read_prune_mode(*tx));
        }
        sw_log::Message("Effective pruning", {"mode", node_settings.prune_mode->to_string()});
    }

    tx.commit(/*renew=*/false);
    chaindata_env.close();
    node_settings.chaindata_env_config.exclusive = chaindata_exclusive;
    node_settings.chaindata_env_config.create = false;  // Has already been created
}

class DummyServerCompletionQueue : public grpc::ServerCompletionQueue {
};

std::pair<std::shared_ptr<silkworm::sentry::api::api_common::SentryClient>, std::optional<std::shared_ptr<silkworm::sentry::Sentry>>> make_sentry(
    silkworm::sentry::Settings sentry_settings,
    const NodeSettings& node_settings,
    silkworm::rpc::ServerContextPool& context_pool,
    sw_db::ROAccess db_access) {
    std::optional<std::shared_ptr<silkworm::sentry::Sentry>> sentry_server;
    std::shared_ptr<silkworm::sentry::api::api_common::SentryClient> sentry_client;

    sw_db::EthStatusDataProvider eth_status_data_provider{db_access, node_settings.chain_config.value()};

    if (node_settings.remote_sentry_addresses.empty()) {
        sentry_settings.data_dir_path = node_settings.data_directory->path();
        // disable GRPC in the embedded sentry
        sentry_settings.api_address = "";

        sentry_server = std::make_shared<silkworm::sentry::Sentry>(std::move(sentry_settings), context_pool);

        // wrap direct client in a session client
        sentry_client = std::make_shared<silkworm::sentry::SessionSentryClient>(
            sentry_server.value(),
            eth_status_data_provider.to_factory_function());
    } else if (node_settings.remote_sentry_addresses.size() == 1) {
        // remote client
        auto remote_sentry_client = std::make_shared<silkworm::sentry::grpc::client::SentryClient>(
            node_settings.remote_sentry_addresses[0],
            *context_pool.next_context().client_grpc_context());
        // wrap remote client in a session client
        sentry_client = std::make_shared<silkworm::sentry::SessionSentryClient>(
            remote_sentry_client,
            eth_status_data_provider.to_factory_function());
    } else {
        std::vector<std::shared_ptr<silkworm::sentry::api::api_common::SentryClient>> clients;

        for (const auto& address_uri : node_settings.remote_sentry_addresses) {
            // remote client
            auto remote_sentry_client = std::make_shared<silkworm::sentry::grpc::client::SentryClient>(
                address_uri,
                *context_pool.next_context().client_grpc_context());
            // wrap remote client in a session client
            auto session_sentry_client = std::make_shared<silkworm::sentry::SessionSentryClient>(
                remote_sentry_client,
                eth_status_data_provider.to_factory_function());
            clients.push_back(session_sentry_client);
        }

        sentry_client = std::make_shared<silkworm::sentry::MultiSentryClient>(std::move(clients));
    }

    return {sentry_client, sentry_server};
}

// main
int main(int argc, char* argv[]) {
    using namespace boost::placeholders;
    using namespace std::chrono;
    using namespace silkworm::concurrency::awaitable_wait_for_one;
    using namespace silkworm::concurrency::awaitable_wait_for_all;

    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);

    try {
        SilkwormSettings settings;
        parse_silkworm_command_line(cli, argc, argv, settings);

        auto& node_settings = settings.node_settings;
        auto& snapshot_settings = settings.snapshot_settings;

        // Initialize logging with cli settings
        sw_log::init(settings.log_settings);
        sw_log::set_thread_name("main-thread");

        // Output BuildInfo
        const auto build_info{silkworm_get_buildinfo()};
        node_settings.build_info =
            "version=" + std::string(build_info->git_branch) + std::string(build_info->project_version) +
            "build=" + std::string(build_info->system_name) + "-" + std::string(build_info->system_processor) +
            " " + std::string(build_info->build_type) +
            "compiler=" + std::string(build_info->compiler_id) +
            " " + std::string(build_info->compiler_version);

        sw_log::Message(
            "Silkworm",
            {"version", std::string(build_info->git_branch) + std::string(build_info->project_version),
             "build",
             std::string(build_info->system_name) + "-" + std::string(build_info->system_processor) + " " +
                 std::string(build_info->build_type),
             "compiler",
             std::string(build_info->compiler_id) + " " + std::string(build_info->compiler_version)});

        // Output mdbx build info
        auto mdbx_ver{mdbx::get_version()};
        auto mdbx_bld{mdbx::get_build()};
        sw_log::Message("libmdbx",
                        {"version", mdbx_ver.git.describe, "build", mdbx_bld.target, "compiler", mdbx_bld.compiler});

        // Check db
        run_preflight_checklist(node_settings);  // Prepare database for takeoff

        auto chaindata_db{sw_db::open_env(node_settings.chaindata_env_config)};

        PreverifiedHashes::load(node_settings.chain_config->chain_id);

        // Start boost asio context for execution timers // TODO(canepat) we need a better solution
        // The following async-thread executor is needed to have graceful shutdown in case of any run exception
        auto timer_executor = [&node_settings]() -> boost::asio::awaitable<void> {
            using asio_guard_type = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
            auto asio_guard = std::make_unique<asio_guard_type>(node_settings.asio_context.get_executor());

            auto run = [&] {
                sw_log::set_thread_name("asio_ctx_timer");
                sw_log::Trace("Asio Timers", {"state", "started"});
                node_settings.asio_context.run();
                sw_log::Trace("Asio Timers", {"state", "stopped"});
            };
            auto stop = [&] { asio_guard.reset(); };
            co_await silkworm::concurrency::async_thread(std::move(run), std::move(stop));
        };
        silkworm::rpc::ServerContextPool context_pool{
            settings.server_settings.context_pool_settings(),
            [] { return std::make_unique<DummyServerCompletionQueue>(); },
        };

        // Resource usage logging
        ResourceUsageLog resource_usage_log(node_settings);

        // Sentry
        auto [sentry_client, sentry_server] = make_sentry(
            std::move(settings.sentry_settings),
            node_settings,
            context_pool,
            sw_db::ROAccess(chaindata_db));
        auto embedded_sentry_run_if_needed = [&sentry_server = sentry_server]() -> boost::asio::awaitable<void> {
            if (sentry_server) {
                co_await sentry_server.value()->run();
            }
        };

        // BackEnd & KV server
        silkworm::EthereumBackEnd backend{
            node_settings,
            &chaindata_db,
            sentry_client,
        };
        const auto node_name{get_node_name_from_build_info(build_info)};
        backend.set_node_name(node_name);

        silkworm::rpc::BackEndKvServer rpc_server{settings.server_settings, backend};

        // Snapshot sync
        if (snapshot_settings.enabled) {
            // Raise file descriptor limit per process
            raise_max_file_descriptors();

            sw_db::RWTxn rw_txn{chaindata_db};

            // Snapshot sync - download chain from peers using snapshot files
            SnapshotSync snapshot_sync{snapshot_settings, node_settings.chain_config.value()};
            snapshot_sync.download_and_index_snapshots(rw_txn);
            rw_txn.commit_and_stop();
        } else {
            sw_log::Info() << "Snapshot sync disabled, no snapshot must be downloaded";
        }

        // Execution: the execution layer engine
        execution::Server execution_server{node_settings, sw_db::RWAccess{chaindata_db}};

        // ChainSync: the chain synchronization process based on the consensus protocol
        execution::LocalClient execution_client{execution_server};
        chainsync::Sync chain_sync_process{
            context_pool.next_io_context(),
            chaindata_db,
            execution_client,
            sentry_client,
            *node_settings.chain_config};

        auto tasks =
            timer_executor() &&
            resource_usage_log.async_run() &&
            rpc_server.async_run() &&
            embedded_sentry_run_if_needed() &&
            execution_server.async_run() &&
            chain_sync_process.async_run();

        // Trap OS signals
        ShutdownSignal shutdown_signal{context_pool.next_io_context()};

        // Go!
        auto run_future = boost::asio::co_spawn(
            context_pool.next_io_context(),
            std::move(tasks) || shutdown_signal.wait(),
            boost::asio::use_future);
        context_pool.start();
        sw_log::Message() << "Silkworm is now running";

        // Wait for shutdown signal or an exception from tasks
        run_future.get();

        // Graceful exit after user shutdown signal
        sw_log::Message() << "Exiting Silkworm";
        return 0;
    } catch (const CLI::ParseError& ex) {
        // Let CLI11 handle any error occurred parsing command-line args
        return cli.exit(ex);
    } catch (const std::exception& ex) {
        // Any exception during run leads to termination
        sw_log::Critical("Unrecoverable failure: exit", {"error", ex.what()});
        return -1;
    } catch (...) {
        // Any unknown exception during run leads to termination
        sw_log::Critical("Unrecoverable failure: exit", {"error", "unexpected exception"});
        return -2;
    }
}
