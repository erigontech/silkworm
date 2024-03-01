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
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/mdbx.hpp>
#include <silkworm/rpc/daemon.hpp>
#include <silkworm/snapshots/repository.hpp>

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

std::vector<SilkwormChainSnapshot> collect_all_snapshots(const SnapshotRepository& snapshot_repository) {
    std::vector<SilkwormHeadersSnapshot> headers_snapshot_sequence;
    std::vector<SilkwormBodiesSnapshot> bodies_snapshot_sequence;
    std::vector<SilkwormTransactionsSnapshot> transactions_snapshot_sequence;

    for (const auto& segment_file : snapshot_repository.get_segment_files()) {
        switch (segment_file.type()) {
            case SnapshotType::headers: {
                const auto* header_snapshot{snapshot_repository.get_header_segment(segment_file)};
                const auto* idx_header_hash{header_snapshot->idx_header_hash()};
                SilkwormHeadersSnapshot raw_headers_snapshot{
                    .segment{
                        .file_path = make_path(segment_file),
                        .memory_address = header_snapshot->memory_file_address(),
                        .memory_length = header_snapshot->memory_file_size()},
                    .header_hash_index{
                        .file_path = make_path(segment_file.index_file()),
                        .memory_address = idx_header_hash->memory_file_address(),
                        .memory_length = idx_header_hash->memory_file_size()}};
                headers_snapshot_sequence.push_back(raw_headers_snapshot);
            } break;
            case SnapshotType::bodies: {
                const auto* body_snapshot{snapshot_repository.get_body_segment(segment_file)};
                const auto* idx_body_number{body_snapshot->idx_body_number()};
                SilkwormBodiesSnapshot raw_bodies_snapshot{
                    .segment{
                        .file_path = make_path(segment_file),
                        .memory_address = body_snapshot->memory_file_address(),
                        .memory_length = body_snapshot->memory_file_size()},
                    .block_num_index{
                        .file_path = make_path(segment_file.index_file()),
                        .memory_address = idx_body_number->memory_file_address(),
                        .memory_length = idx_body_number->memory_file_size()}};
                bodies_snapshot_sequence.push_back(raw_bodies_snapshot);
            } break;
            case SnapshotType::transactions: {
                const auto* tx_snapshot{snapshot_repository.get_tx_segment(segment_file)};
                const auto* idx_txn_hash{tx_snapshot->idx_txn_hash()};
                const auto* idx_txn_hash_2_block{tx_snapshot->idx_txn_hash_2_block()};
                SilkwormTransactionsSnapshot raw_transactions_snapshot{
                    .segment{
                        .file_path = make_path(segment_file),
                        .memory_address = tx_snapshot->memory_file_address(),
                        .memory_length = tx_snapshot->memory_file_size()},
                    .tx_hash_index{
                        .file_path = make_path(segment_file.index_file()),
                        .memory_address = idx_txn_hash->memory_file_address(),
                        .memory_length = idx_txn_hash->memory_file_size()},
                    .tx_hash_2_block_index{
                        .file_path = make_path(segment_file.index_file_for_type(SnapshotType::transactions_to_block)),
                        .memory_address = idx_txn_hash_2_block->memory_file_address(),
                        .memory_length = idx_txn_hash_2_block->memory_file_size()}};
                transactions_snapshot_sequence.push_back(raw_transactions_snapshot);
            } break;
            default:
                ensure(false, [&]() { return "unexpected snapshot type: " + std::string{magic_enum::enum_name(segment_file.type())}; });
        }
    }

    ensure(headers_snapshot_sequence.size() == snapshot_repository.header_snapshots_count(), "invalid header snapshot count");
    ensure(bodies_snapshot_sequence.size() == snapshot_repository.body_snapshots_count(), "invalid body snapshot count");
    ensure(transactions_snapshot_sequence.size() == snapshot_repository.tx_snapshots_count(), "invalid tx snapshot count");

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

int execute_blocks(SilkwormHandle handle, ExecuteBlocksSettings settings, const SnapshotRepository& repository, const DataDirectory& data_dir) {
    // Open chain database
    silkworm::db::EnvConfig config{
        .path = data_dir.chaindata().path().string(),
        .readonly = false,
        .exclusive = true};
    ::mdbx::env_managed env{silkworm::db::open_env(config)};
    ::mdbx::txn_managed rw_txn{env.start_write()};

    db::ROTxnUnmanaged ro_txn{rw_txn};
    const auto chain_config{db::read_chain_config(ro_txn)};
    ensure(chain_config.has_value(), "no chain configuration in database");
    const auto chain_id{chain_config->chain_id};

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
    const auto start_block{settings.start_block};
    const auto max_block{settings.max_block};
    const auto batch_size{settings.batch_size};
    const auto write_change_sets{settings.write_change_sets};
    const auto write_receipts{settings.write_receipts};
    const auto write_call_traces{settings.write_call_traces};
    BlockNum last_executed_block{0};
    int mdbx_error_code{0};
    SILK_INFO << "Execute blocks count=" << (max_block - start_block + 1) << " batch_size=" << batch_size << " start";
    const int status_code = silkworm_execute_blocks(
        handle, &*rw_txn, chain_id, start_block, max_block, batch_size, write_change_sets, write_receipts, write_call_traces, &last_executed_block, &mdbx_error_code);
    SILK_INFO << "Execute blocks count=" << (max_block - start_block + 1) << " batch_size=" << batch_size << " done";

    if (status_code != SILKWORM_OK) {
        SILK_ERROR << "silkworm_execute_blocks failed [code=" << std::to_string(status_code)
                   << (status_code == SILKWORM_MDBX_ERROR ? " mdbx_error_code=" + std::to_string(mdbx_error_code) : "")
                   << "]";
    }
    SILK_INFO << "Last executed block: " << last_executed_block;

    rw_txn.abort();  // We do *not* want to commit anything

    return status_code;
}

int build_indexes(SilkwormHandle handle, const BuildIndexesSettings& settings, const SnapshotRepository& repository, const DataDirectory& data_dir) {
    SILK_INFO << "Building indexes for snapshots: " << settings.snapshot_names;

    std::vector<SilkwormMemoryMappedFile*> snapshots;
    // Parse snapshot paths and create memory mapped files
    for (auto& snapshot_name : settings.snapshot_names) {
        auto raw_snapshot_path = data_dir.snapshots().path() / snapshot_name;
        auto snapshot_path = SnapshotPath::parse(raw_snapshot_path);
        if (!snapshot_path.has_value())
            throw std::runtime_error("Invalid snapshot path");

        const Snapshot* snapshot{nullptr};
        switch (snapshot_path->type()) {
            case headers:
                snapshot = repository.get_header_segment(*snapshot_path);
                break;
            case bodies:
                snapshot = repository.get_body_segment(*snapshot_path);
                break;
            case transactions:
            case transactions_to_block:
                snapshot = repository.get_tx_segment(*snapshot_path);
                break;
            default:
                throw std::runtime_error("Invalid snapshot type");
        }
        if (!snapshot) {
            throw std::runtime_error("Snapshot not found in the repository:" + snapshot_name);
        }

        auto mmf = new SilkwormMemoryMappedFile();
        mmf->file_path = make_path(snapshot->path());
        mmf->memory_address = snapshot->memory_file_address();
        mmf->memory_length = snapshot->memory_file_size();
        snapshots.push_back(mmf);
    }

    // Call api to build indexes
    const auto start_time{std::chrono::high_resolution_clock::now()};

    const int status_code = silkworm_build_recsplit_indexes(handle, snapshots.data(), snapshots.size());
    if (status_code != SILKWORM_OK) return status_code;

    auto elapsed = std::chrono::high_resolution_clock::now() - start_time;
    SILK_INFO << "Building indexes for snapshots done in "
              << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << "ms";

    // Free memory mapped files
    for (auto snapshot : snapshots) {
        delete[] snapshot->file_path;
        delete snapshot;
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

    const int status_code{silkworm_start_rpcdaemon(handle, &*env)};
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
        SnapshotRepository repository{snapshot_settings};
        repository.reopen_folder();

        int status_code = -1;
        if (settings.execute_blocks_settings) {
            // Execute specified block range using Silkworm API library
            status_code = execute_blocks(handle, *settings.execute_blocks_settings, repository, data_dir);
        } else if (settings.build_indexes_settings) {
            // Build index for a specific snapshot using Silkworm API library
            status_code = build_indexes(handle, *settings.build_indexes_settings, repository, data_dir);
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
