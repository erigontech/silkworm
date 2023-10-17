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
#include <boost/dll.hpp>
#include <boost/process/environment.hpp>
#include <magic_enum.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <mdbx.h++>
#pragma GCC diagnostic pop

#include <silkworm/api/silkworm_api.h>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/mdbx.hpp>
#include <silkworm/node/snapshot/repository.hpp>

#include "../common/common.hpp"

using namespace silkworm;
using namespace silkworm::snapshot;
using namespace silkworm::cmd::common;

const char* kSilkwormApiLibUndecoratedPath = "../../silkworm/api/silkworm_api";
const char* kSilkwormInitSymbol = "silkworm_init";
const char* kSilkwormBuildRecSplitIndexes = "silkworm_build_recsplit_indexes";
const char* kSilkwormAddSnapshotSymbol = "silkworm_add_snapshot";
const char* kSilkwormExecuteBlocksSymbol = "silkworm_execute_blocks";
const char* kSilkwormFiniSymbol = "silkworm_fini";

auto kSilkwormApiLibPath{boost::dll::shared_library::decorate(kSilkwormApiLibUndecoratedPath)};

//! Function signature for silkworm_init C API
using SilkwormInitSig = int(SilkwormHandle**);

//! Function signature for silkworm_build_recsplit_indexes C API
using SilkwormBuildRecSplitIndexes = int(SilkwormHandle*, SilkwormMemoryMappedFile*[], int len);

//! Function signature for silkworm_add_snapshot C API
using SilkwormAddSnapshotSig = int(SilkwormHandle*, SilkwormChainSnapshot*);

//! Function signature for silkworm_execute_blocks C API
using SilkwormExecuteBlocksSig =
    int(SilkwormHandle*, MDBX_txn*, uint64_t, uint64_t, uint64_t, uint64_t, bool, uint64_t*, int*);

//! Function signature for silkworm_fini C API
using SilkwormFiniSig = int(SilkwormHandle*);

struct ExecuteBlocksSettings {
    bool present;
    BlockNum start_block{1};
    BlockNum max_block{1};
    uint64_t batch_size{1};
    bool write_receipts{false};
};

struct BuildIdxesSettings {
    bool present;
    std::string snapshot_repo;
    std::vector<std::string> snapshot_names;
};

void parse_command_line(int argc, char* argv[], CLI::App& app,
                        log::Settings& log_settings,
                        std::string& silkworm_api_lib_path,
                        std::string& data_dir,
                        ExecuteBlocksSettings& exec_blocks_settings,
                        BuildIdxesSettings& build_idxes_settings) {
    app.require_subcommand(1);  // At least 1 subcommand is required

    // logging
    add_logging_options(app, log_settings);

    // repository
    app.add_option("--lib_path", silkworm_api_lib_path, "Path to silkworm_lib");
    app.add_option("--data_dir", data_dir, "Path to data directory");

    // execute sub-command
    auto cmd_execute = app.add_subcommand("execute", "Execute blocks");

    cmd_execute->add_option("--from", exec_blocks_settings.start_block, "The start block number to execute")
        ->capture_default_str()
        ->check(CLI::Range(uint64_t(1), std::numeric_limits<BlockNum>::max()));
    cmd_execute->add_option("--to", exec_blocks_settings.max_block, "The maximum block number to execute")
        ->capture_default_str()
        ->check(CLI::Range(uint64_t(1), std::numeric_limits<BlockNum>::max()));

    cmd_execute->add_option("--batch_size", exec_blocks_settings.batch_size, "The block batch size to use")
        ->capture_default_str()
        ->check(CLI::Range(uint64_t(1), std::numeric_limits<uint64_t>::max()));

    cmd_execute->add_flag("--write_receipts", exec_blocks_settings.write_receipts, "Flag indicating if transaction receipts must be written or not")
        ->capture_default_str();

    // build-indexes sub-command
    auto cmd_build_idxes = app.add_subcommand("build_idxes", "Build indexes");

    cmd_build_idxes->add_option("--snapshot_names", build_idxes_settings.snapshot_names, "Snapshots to index")->delimiter(',')->required();

    // parte
    app.parse(argc, argv);

    // check subcommand presence
    exec_blocks_settings.present = app.got_subcommand(cmd_execute);
    build_idxes_settings.present = app.got_subcommand(cmd_build_idxes);
}

const char* make_path(const snapshot::SnapshotPath& p) {
    const auto path_string{p.path().string()};
    char* path = new char[path_string.size()];
    std::memcpy(path, path_string.data(), path_string.size());
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
                ensure(false, "unexpected snapshot type: " + std::string{magic_enum::enum_name(segment_file.type())});
        }
    }

    ensure(headers_snapshot_sequence.size() == snapshot_repository.header_snapshots_count(), "invalid header snapshot count");
    ensure(bodies_snapshot_sequence.size() == snapshot_repository.body_snapshots_count(), "invalid body snapshot count");
    ensure(transactions_snapshot_sequence.size() == snapshot_repository.tx_snapshots_count(), "invalid tx snapshot count");

    std::vector<SilkwormChainSnapshot> snapshot_sequence;
    snapshot_sequence.reserve(headers_snapshot_sequence.size());
    for (std::size_t i{0}; i < headers_snapshot_sequence.size(); ++i) {
        SilkwormChainSnapshot chain_snapshot{
            std::move(headers_snapshot_sequence[i]),
            std::move(bodies_snapshot_sequence[i]),
            std::move(transactions_snapshot_sequence[i])};
        snapshot_sequence.push_back(chain_snapshot);
    }
    return snapshot_sequence;
}

int main(int argc, char* argv[]) {
    CLI::App app{"Execute"};

    try {
        log::Settings log_settings;
        std::string silkworm_api_lib_path;
        std::string data_dir_path;
        ExecuteBlocksSettings exec_cmd;
        BuildIdxesSettings idxes_cmd;
        parse_command_line(argc, argv, app, log_settings, silkworm_api_lib_path, data_dir_path, exec_cmd, idxes_cmd);

        log::init(log_settings);

        const auto pid = boost::this_process::get_id();
        SILK_INFO << "Execute starting [pid=" << std::to_string(pid) << "]";

        if (not silkworm_api_lib_path.empty())
            kSilkwormApiLibPath = silkworm_api_lib_path;

        silkworm::DataDirectory data_dir{data_dir_path.empty() ? DataDirectory::get_default_storage_path() : std::filesystem::path(data_dir_path)};

        // Import the silkworm_init symbol from Silkworm API library
        const auto silkworm_init{
            boost::dll::import_symbol<SilkwormInitSig>(kSilkwormApiLibPath, kSilkwormInitSymbol)};

        // Import the silkworm_build_recsplit_indexes symbol from Silkworm API library
        const auto silkworm_build_recsplit_indexes{
            boost::dll::import_symbol<SilkwormBuildRecSplitIndexes>(kSilkwormApiLibPath, kSilkwormBuildRecSplitIndexes)};

        // Import the silkworm_add_snapshot symbol from Silkworm API library
        const auto silkworm_add_snapshot{
            boost::dll::import_symbol<SilkwormAddSnapshotSig>(kSilkwormApiLibPath, kSilkwormAddSnapshotSymbol)};

        // Import the silkworm_execute_blocks symbol from Silkworm API library
        const auto silkworm_execute_blocks{
            boost::dll::import_symbol<SilkwormExecuteBlocksSig>(kSilkwormApiLibPath, kSilkwormExecuteBlocksSymbol)};

        // Import the silkworm_fini symbol from Silkworm API library
        const auto silkworm_fini{
            boost::dll::import_symbol<SilkwormFiniSig>(kSilkwormApiLibPath, kSilkwormFiniSymbol)};

        // Initialize Silkworm API library
        SilkwormHandle* handle{nullptr};
        const int init_status_code = silkworm_init(&handle);
        if (init_status_code != SILKWORM_OK) {
            SILK_ERROR << "silkworm_init failed [code=" << std::to_string(init_status_code) << "]";
            return init_status_code;
        }

        // Add snapshots to Silkworm API library
        SnapshotSettings settings = {};
        settings.repository_dir = data_dir.snapshots().path();
        SnapshotRepository repository{settings};
        repository.reopen_folder();

        int status_code = -1;
        if (exec_cmd.present) {  // Execute specified block range using Silkworm API library
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
            const auto start_block{exec_cmd.start_block};
            const auto max_block{exec_cmd.max_block};
            const auto batch_size{exec_cmd.batch_size};
            const auto write_receipts{exec_cmd.write_receipts};
            BlockNum last_executed_block{0};
            int mdbx_error_code{0};
            SILK_INFO << "Execute blocks count=" << (max_block - start_block + 1) << " batch_size=" << batch_size << " start";
            status_code = silkworm_execute_blocks(handle, &*rw_txn, chain_id, start_block, max_block, batch_size, write_receipts, &last_executed_block, &mdbx_error_code);
            SILK_INFO << "Execute blocks count=" << (max_block - start_block + 1) << " batch_size=" << batch_size << " done";

            if (status_code != SILKWORM_OK) {
                SILK_ERROR << "silkworm_execute_blocks failed [code=" << std::to_string(status_code)
                           << (status_code == SILKWORM_MDBX_ERROR ? " mdbx_error_code=" + std::to_string(mdbx_error_code) : "")
                           << "]";
            }
            SILK_INFO << "Last executed block: " << last_executed_block;

            rw_txn.abort();  // We do *not* want to commit anything

        } else if (idxes_cmd.present) {  // Build index for a specific snapshot using Silkworm API library
            SILK_INFO << "Building indexes for snapshots: " << idxes_cmd.snapshot_names;

            std::vector<SilkwormMemoryMappedFile*> snapshots;
            // Parse snapshot paths and create memory mapped files
            for (auto& snapshot_name : idxes_cmd.snapshot_names) {
                auto raw_snapshot_path = data_dir.snapshots().path() / snapshot_name;
                auto snapshot_path = SnapshotPath::parse(raw_snapshot_path);
                if (!snapshot_path.has_value())
                    throw std::runtime_error("Invalid snapshot path");

                const Snapshot* snapshot = nullptr;
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

                if (!snapshot)
                    throw std::runtime_error("Snapshot not found in the repository:" + snapshot_name);

                auto path = snapshot->fs_path().string();
                char* raw_path = new char[path.length() + 1];
                std::strcpy(raw_path, path.c_str());

                auto mmf = new SilkwormMemoryMappedFile();
                mmf->file_path = raw_path;
                mmf->memory_address = snapshot->memory_file_address();
                mmf->memory_length = snapshot->memory_file_size();
                snapshots.push_back(mmf);
            }

            // Call api to build indexes
            const auto start_time{std::chrono::high_resolution_clock::now()};

            status_code = silkworm_build_recsplit_indexes(handle, snapshots.data(), snapshots.size());
            if (status_code != SILKWORM_OK) {
                SILK_ERROR << "silkworm_build_recsplit_indexes failed [code=" << std::to_string(status_code) << "]";
                return status_code;
            }

            auto elapsed = std::chrono::high_resolution_clock::now() - start_time;
            SILK_INFO << "Building indexes for snapshots done in "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << "ms";

            // Free memory mapped files
            for (auto snapshot : snapshots) {
                delete[] snapshot->file_path;
                delete snapshot;
            }
        } else {
            SILK_ERROR << "No sub-command chosen";
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
