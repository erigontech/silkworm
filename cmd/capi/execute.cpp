/*
   Copyright 2023 The Silkworm Authors

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

#include <limits>
#include <stdexcept>

#include <CLI/CLI.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>
#include <magic_enum.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <mdbx.h++>
#pragma GCC diagnostic pop

#include <silkworm/capi/silkworm.h>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/db/snapshots/repository.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/daemon.hpp>

#include "../common/common.hpp"

using namespace silkworm;
using namespace silkworm::snapshots;
using namespace silkworm::cmd::common;

struct ExecuteBlocksSettings {
    BlockNum start_block{1};
    BlockNum max_block{1};
    uint64_t batch_size{1};
    bool write_change_sets{true};
    bool write_receipts{true};
    bool write_call_traces{true};
    bool use_internal_txn{false};
};

struct BuildIndexesSettings {
    std::vector<std::string> snapshot_names;
};

struct Settings {
    log::Settings log_settings;
    std::string data_folder;
    std::optional<ExecuteBlocksSettings> execute_blocks_settings;
    std::optional<BuildIndexesSettings> build_indexes_settings;
    std::optional<rpc::DaemonSettings> rpcdaemon_settings;
};

void parse_command_line(int argc, char* argv[], CLI::App& app, Settings& settings) {
    app.require_subcommand(1);  // At least 1 subcommand is required

    // logging
    add_logging_options(app, settings.log_settings);

    // repository
    app.add_option("--datadir", settings.data_folder, "Path to data directory");

    // execute sub-command
    auto cmd_execute = app.add_subcommand("execute", "Execute blocks");

    ExecuteBlocksSettings exec_blocks_settings;
    cmd_execute->add_option("--from", exec_blocks_settings.start_block, "The start block number to execute")
        ->capture_default_str()
        ->check(CLI::Range(uint64_t{1}, std::numeric_limits<BlockNum>::max()));
    cmd_execute->add_option("--to", exec_blocks_settings.max_block, "The maximum block number to execute")
        ->capture_default_str()
        ->check(CLI::Range(uint64_t{1}, std::numeric_limits<BlockNum>::max()));

    cmd_execute->add_option("--batch_size", exec_blocks_settings.batch_size, "The block batch size to use")
        ->capture_default_str()
        ->check(CLI::Range(uint64_t{1}, std::numeric_limits<uint64_t>::max()));

    cmd_execute->add_flag("--write_change_sets", exec_blocks_settings.write_change_sets)
        ->description("Flag indicating if state changes must be written or not")
        ->capture_default_str();

    cmd_execute->add_flag("--write_receipts", exec_blocks_settings.write_receipts)
        ->description("Flag indicating if transaction receipts must be written or not")
        ->capture_default_str();

    cmd_execute->add_flag("--write_call_traces", exec_blocks_settings.write_call_traces)
        ->description("Flag indicating if execution call traces must be written or not")
        ->capture_default_str();

    cmd_execute->add_flag("--use_internal_txn", exec_blocks_settings.use_internal_txn)
        ->description(
            "Flag indicating if internal MDBX transaction must be used. "
            "Please be aware that when this option is chosen the block execution result *will* be saved to the db")
        ->capture_default_str();

    // build indexes sub-command
    auto cmd_build_indexes = app.add_subcommand("build_indexes", "Build indexes");

    BuildIndexesSettings build_indexes_settings;
    cmd_build_indexes->add_option("--snapshot_names", build_indexes_settings.snapshot_names, "Snapshot to index")->delimiter(',')->required();

    // rpcdaemon sub-command
    auto cmd_rpcdaemon = app.add_subcommand("rpcdaemon", "Start RPC Daemon");

    rpc::DaemonSettings rpcdaemon_settings{
        .datadir = settings.data_folder};

    // parse command line
    app.parse(argc, argv);

    // Force logging options to have consistent format with Silkworm API library (matching Erigon in turns)
    settings.log_settings.log_utc = false;
    settings.log_settings.log_timezone = false;
    settings.log_settings.log_trim = true;

    // check subcommand presence
    if (app.got_subcommand(cmd_execute)) {
        settings.execute_blocks_settings = exec_blocks_settings;
    } else if (app.got_subcommand(cmd_build_indexes)) {
        settings.build_indexes_settings = std::move(build_indexes_settings);
    } else if (app.got_subcommand(cmd_rpcdaemon)) {
        settings.rpcdaemon_settings = std::move(rpcdaemon_settings);
    }
}

const char* make_path(const snapshots::SnapshotPath& p) {
    const auto path_string{p.path().string()};
    char* path = new char[path_string.size() + 1];
    std::strcpy(path, path_string.c_str());
    return path;
}

std::vector<SilkwormChainSnapshot> collect_all_snapshots(SnapshotRepository& snapshot_repository) {
    std::vector<SilkwormHeadersSnapshot> headers_snapshot_sequence;
    std::vector<SilkwormBodiesSnapshot> bodies_snapshot_sequence;
    std::vector<SilkwormTransactionsSnapshot> transactions_snapshot_sequence;

    snapshot_repository.view_bundles(
        [&](const SnapshotBundle& bundle) {
            {
                SilkwormHeadersSnapshot raw_headers_snapshot{
                    .segment{
                        .file_path = make_path(bundle.header_snapshot.path()),
                        .memory_address = bundle.header_snapshot.memory_file_region().data(),
                        .memory_length = bundle.header_snapshot.memory_file_region().size(),
                    },
                    .header_hash_index{
                        .file_path = make_path(bundle.idx_header_hash.path()),
                        .memory_address = bundle.idx_header_hash.memory_file_region().data(),
                        .memory_length = bundle.idx_header_hash.memory_file_region().size(),
                    },
                };
                headers_snapshot_sequence.push_back(raw_headers_snapshot);
            }
            {
                SilkwormBodiesSnapshot raw_bodies_snapshot{
                    .segment{
                        .file_path = make_path(bundle.body_snapshot.path()),
                        .memory_address = bundle.body_snapshot.memory_file_region().data(),
                        .memory_length = bundle.body_snapshot.memory_file_region().size(),
                    },
                    .block_num_index{
                        .file_path = make_path(bundle.idx_body_number.path()),
                        .memory_address = bundle.idx_body_number.memory_file_region().data(),
                        .memory_length = bundle.idx_body_number.memory_file_region().size(),
                    },
                };
                bodies_snapshot_sequence.push_back(raw_bodies_snapshot);
            }
            {
                SilkwormTransactionsSnapshot raw_transactions_snapshot{
                    .segment{
                        .file_path = make_path(bundle.txn_snapshot.path()),
                        .memory_address = bundle.txn_snapshot.memory_file_region().data(),
                        .memory_length = bundle.txn_snapshot.memory_file_region().size(),
                    },
                    .tx_hash_index{
                        .file_path = make_path(bundle.idx_txn_hash.path()),
                        .memory_address = bundle.idx_txn_hash.memory_file_region().data(),
                        .memory_length = bundle.idx_txn_hash.memory_file_region().size(),
                    },
                    .tx_hash_2_block_index{
                        .file_path = make_path(bundle.idx_txn_hash_2_block.path()),
                        .memory_address = bundle.idx_txn_hash_2_block.memory_file_region().data(),
                        .memory_length = bundle.idx_txn_hash_2_block.memory_file_region().size(),
                    },
                };
                transactions_snapshot_sequence.push_back(raw_transactions_snapshot);
            }
            return true;
        });

    ensure(headers_snapshot_sequence.size() == snapshot_repository.bundles_count(), "invalid header snapshot count");
    ensure(bodies_snapshot_sequence.size() == snapshot_repository.bundles_count(), "invalid body snapshot count");
    ensure(transactions_snapshot_sequence.size() == snapshot_repository.bundles_count(), "invalid tx snapshot count");

    std::vector<SilkwormChainSnapshot> snapshot_sequence;
    snapshot_sequence.reserve(headers_snapshot_sequence.size());
    for (std::size_t i{0}; i < headers_snapshot_sequence.size(); ++i) {
        SilkwormChainSnapshot chain_snapshot{
            headers_snapshot_sequence[i],
            bodies_snapshot_sequence[i],
            transactions_snapshot_sequence[i],
        };
        snapshot_sequence.push_back(chain_snapshot);
    }
    return snapshot_sequence;
}

int execute_with_internal_txn(SilkwormHandle handle, ExecuteBlocksSettings settings, ::mdbx::env& env) {
    db::ROTxnManaged ro_txn{env};
    const auto chain_config{db::read_chain_config(ro_txn)};
    ensure(chain_config.has_value(), "no chain configuration in database");
    const auto chain_id{chain_config->chain_id};
    ro_txn.abort();

    BlockNum last_executed_block{0};
    int mdbx_error_code{0};
    const uint64_t count{settings.max_block - settings.start_block + 1};
    SILK_DEBUG << "Execute blocks start_block=" << settings.start_block << " end_block=" << settings.max_block << " count=" << count << " batch_size=" << settings.batch_size << " start";
    const int status_code = silkworm_execute_blocks_perpetual(
        handle, env, chain_id,
        settings.start_block, settings.max_block, settings.batch_size,
        settings.write_change_sets, settings.write_receipts, settings.write_call_traces,
        &last_executed_block, &mdbx_error_code);
    SILK_DEBUG << "Execute blocks start_block=" << settings.start_block << " end_block=" << settings.max_block << " count=" << count << " batch_size=" << settings.batch_size << " done";

    if (status_code != SILKWORM_OK) {
        SILK_ERROR << "execute_with_internal_txn failed [code=" << std::to_string(status_code)
                   << (status_code == SILKWORM_MDBX_ERROR ? " mdbx_error_code=" + std::to_string(mdbx_error_code) : "")
                   << "]";
        return status_code;
    }

    SILK_INFO << "Last executed block: " << last_executed_block;
    return status_code;
}

int execute_with_external_txn(SilkwormHandle handle, ExecuteBlocksSettings settings, ::mdbx::env& env) {
    db::RWTxnManaged rw_txn{env};

    const auto chain_config{db::read_chain_config(rw_txn)};
    ensure(chain_config.has_value(), "no chain configuration in database");
    const auto chain_id{chain_config->chain_id};

    auto start_block{settings.start_block};
    const auto max_block{settings.max_block};
    while (start_block <= max_block) {
        BlockNum last_executed_block{0};
        int mdbx_error_code{0};
        const int status_code = silkworm_execute_blocks_ephemeral(
            handle, *rw_txn, chain_id,
            settings.start_block, settings.max_block, settings.batch_size,
            settings.write_change_sets, settings.write_receipts, settings.write_call_traces,
            &last_executed_block, &mdbx_error_code);

        if (status_code != SILKWORM_OK) {
            SILK_ERROR << "execute_with_external_txn failed [code=" << std::to_string(status_code)
                       << (status_code == SILKWORM_MDBX_ERROR ? " mdbx_error_code=" + std::to_string(mdbx_error_code) : "")
                       << "] last executed block: " << last_executed_block;
            return status_code;
        }
        start_block = last_executed_block + 1;
    }

    SILK_INFO << "Last executed block: " << max_block;
    return SILKWORM_OK;
}

int execute_blocks(SilkwormHandle handle, ExecuteBlocksSettings settings, SnapshotRepository& repository, const DataDirectory& data_dir) {
    // Open chain database
    silkworm::db::EnvConfig config{
        .path = data_dir.chaindata().path().string(),
        .readonly = false,
        .exclusive = true};
    ::mdbx::env_managed env{silkworm::db::open_env(config)};

    // Collect all snapshots
    auto all_chain_snapshots{collect_all_snapshots(repository)};
    [[maybe_unused]] auto _ = gsl::finally([&]() {
        for (auto& chain_snapshot : all_chain_snapshots) {
            delete[] chain_snapshot.headers.segment.file_path;
            delete[] chain_snapshot.headers.header_hash_index.file_path;
            delete[] chain_snapshot.bodies.segment.file_path;
            delete[] chain_snapshot.bodies.block_num_index.file_path;
            delete[] chain_snapshot.transactions.segment.file_path;
            delete[] chain_snapshot.transactions.tx_hash_index.file_path;
            delete[] chain_snapshot.transactions.tx_hash_2_block_index.file_path;
        }
    });
    for (auto& chain_snapshot : all_chain_snapshots) {
        const int add_snapshot_status_code{silkworm_add_snapshot(handle, &chain_snapshot)};
        if (add_snapshot_status_code != SILKWORM_OK) {
            SILK_ERROR << "silkworm_add_snapshot failed [code=" << std::to_string(add_snapshot_status_code) << "]";
            return add_snapshot_status_code;
        }
    }

    // Execute blocks
    if (settings.use_internal_txn) {
        return execute_with_internal_txn(handle, settings, env);
    } else {
        return execute_with_external_txn(handle, settings, env);
    }
}

int build_indexes(SilkwormHandle handle, const BuildIndexesSettings& settings, const DataDirectory& data_dir) {
    SILK_INFO << "Building indexes for snapshots: " << settings.snapshot_names;

    std::vector<Snapshot> snapshots;
    std::vector<SilkwormMemoryMappedFile*> snapshot_files;
    // Parse snapshot paths and create memory mapped files
    for (auto& snapshot_name : settings.snapshot_names) {
        auto raw_snapshot_path = data_dir.snapshots().path() / snapshot_name;
        auto snapshot_path = SnapshotPath::parse(raw_snapshot_path);
        if (!snapshot_path.has_value())
            throw std::runtime_error("Invalid snapshot path");

        Snapshot& snapshot = snapshots.emplace_back(*snapshot_path);
        snapshot.reopen_segment();

        auto mmf = new SilkwormMemoryMappedFile{
            .file_path = make_path(*snapshot_path),
            .memory_address = snapshot.memory_file_region().data(),
            .memory_length = snapshot.memory_file_region().size(),
        };
        snapshot_files.push_back(mmf);
    }

    // Call api to build indexes
    const auto start_time{std::chrono::high_resolution_clock::now()};

    const int status_code = silkworm_build_recsplit_indexes(handle, snapshot_files.data(), snapshot_files.size());
    if (status_code != SILKWORM_OK) return status_code;

    auto elapsed = std::chrono::high_resolution_clock::now() - start_time;
    SILK_INFO << "Building indexes for snapshots done in "
              << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << "ms";

    // Free memory mapped files
    for (auto mmf : snapshot_files) {
        delete[] mmf->file_path;
        delete mmf;
    }

    return SILKWORM_OK;
}

int start_rpcdaemon(SilkwormHandle handle, const rpc::DaemonSettings& /*settings*/, const DataDirectory& data_dir) {
    // Start execution context dedicated to handling termination signals
    boost::asio::io_context signal_context;
    boost::asio::signal_set signals{signal_context, SIGINT, SIGTERM};
    SILK_DEBUG << "Signals registered on signal_context " << &signal_context;
    signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
        if (signal_number == SIGINT) std::cout << "\n";
        SILK_INFO << "Signal number: " << signal_number << " caught, error: " << error.message();
        const int status_code{silkworm_stop_rpcdaemon(handle)};
        if (status_code != SILKWORM_OK) {
            SILK_ERROR << "silkworm_stop_rpcdaemon failed [code=" << std::to_string(status_code) << "]";
        }
    });

    // Open chain database
    silkworm::db::EnvConfig config{
        .path = data_dir.chaindata().path().string(),
        .readonly = false,
        .exclusive = true};
    ::mdbx::env_managed env{silkworm::db::open_env(config)};

    SilkwormRpcSettings settings{};
    const int status_code{silkworm_start_rpcdaemon(handle, &*env, &settings)};
    if (status_code != SILKWORM_OK) {
        SILK_ERROR << "silkworm_start_rpcdaemon failed [code=" << std::to_string(status_code) << "]";
    }

    signal_context.run();

    return SILKWORM_OK;
}

int main(int argc, char* argv[]) {
    CLI::App app{"Execute"};

    try {
        log::Settings log_settings;
        Settings settings;
        parse_command_line(argc, argv, app, settings);

        log::init(settings.log_settings);

        const auto pid = boost::this_process::get_id();
        SILK_INFO << "Execute starting [pid=" << std::to_string(pid) << "]";

        DataDirectory data_dir{
            settings.data_folder.empty() ? DataDirectory::get_default_storage_path() : std::filesystem::path(settings.data_folder)};

        // Initialize Silkworm API library
        SilkwormHandle handle{nullptr};

        SilkwormSettings silkworm_settings{};
        std::string data_dir_path = data_dir.path().string();
        if (data_dir_path.size() >= SILKWORM_PATH_SIZE) {
            SILK_ERROR << "datadir path too long [data_dir_path=" << data_dir_path << "]";
            return -1;
        }
        strncpy(silkworm_settings.data_dir_path, data_dir_path.c_str(), SILKWORM_PATH_SIZE - 1);

        SILK_INFO << "libmdbx version: " << silkworm_libmdbx_version();
        strncpy(silkworm_settings.libmdbx_version, ::mdbx::get_version().git.describe, sizeof(silkworm_settings.libmdbx_version) - 1);

        const int init_status_code = silkworm_init(&handle, &silkworm_settings);
        if (init_status_code != SILKWORM_OK) {
            SILK_ERROR << "silkworm_init failed [code=" << std::to_string(init_status_code) << "]";
            return init_status_code;
        }

        // Add snapshots to Silkworm API library
        SnapshotSettings snapshot_settings{};
        snapshot_settings.repository_dir = data_dir.snapshots().path();

        int status_code = -1;
        if (settings.execute_blocks_settings) {
            // Execute specified block range using Silkworm API library
            SnapshotRepository repository{snapshot_settings};
            repository.reopen_folder();
            status_code = execute_blocks(handle, *settings.execute_blocks_settings, repository, data_dir);
        } else if (settings.build_indexes_settings) {
            // Build index for a specific snapshot using Silkworm API library
            status_code = build_indexes(handle, *settings.build_indexes_settings, data_dir);
        } else if (settings.rpcdaemon_settings) {
            // Start RPC Daemon using Silkworm API library
            status_code = start_rpcdaemon(handle, *settings.rpcdaemon_settings, data_dir);
        }

        // Finalize Silkworm API library
        const int fini_status_code = silkworm_fini(handle);
        if (fini_status_code != SILKWORM_OK) {
            SILK_ERROR << "silkworm_fini failed [code=" << std::to_string(fini_status_code) << "]";
            return fini_status_code;
        }

        SILK_INFO << "Exiting [pid=" << std::to_string(pid) << "]";
        return status_code;
    } catch (const CLI::ParseError& pe) {
        return app.exit(pe);
    } catch (const std::exception& e) {
        SILK_CRIT << "Exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        SILK_CRIT << "Exiting due to unexpected exception";
        return -3;
    }
}
