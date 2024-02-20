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

#include "silkworm.h"

#include <charconv>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <absl/strings/str_split.h>

#include <silkworm/buildinfo.h>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/call_tracer.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/infra/common/bounded_buffer.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>
#include <silkworm/node/snapshots/index.hpp>

#include "instance.hpp"

using namespace std::chrono_literals;
using namespace silkworm;

static MemoryMappedRegion make_region(const SilkwormMemoryMappedFile& mmf) {
    return {mmf.memory_address, mmf.memory_length};
}

//! Log configuration matching Erigon log format
static log::Settings kLogSettingsLikeErigon{
    .log_utc = false,       // display local time
    .log_timezone = false,  // no timezone ID
    .log_trim = true,       // compact rendering (i.e. no whitespaces)
};
static constexpr size_t kMaxBlockBufferSize{100};

using SteadyTimePoint = std::chrono::time_point<std::chrono::steady_clock>;

//! The progress reached by the block execution process
struct ExecutionProgress {
    SteadyTimePoint start_time;
    SteadyTimePoint end_time;
    size_t processed_blocks{0};
    size_t processed_transactions{0};
    size_t processed_gas{0};
    float gas_state_perc{0.0};
};

//! Kind of match to perform between Erigon and Silkworm libmdbx versions
enum class MdbxVersionCheck : uint8_t {
    kNone,      /// no check at all
    kExact,     /// git-describe versions must match perfectly
    kSemantic,  /// compare semantic versions (<M1.m1.p1> == <M2.m2.p2>)
};

static bool is_compatible_mdbx_version(std::string_view their_version, std::string_view our_version, MdbxVersionCheck check) {
    SILK_TRACE << "is_compatible_mdbx_version their_version: " << their_version << " our_version: " << our_version;
    bool compatible{false};
    switch (check) {
        case MdbxVersionCheck::kNone: {
            compatible = true;
        } break;
        case MdbxVersionCheck::kExact: {
            compatible = their_version == our_version;
        } break;
        case MdbxVersionCheck::kSemantic: {
            const std::vector<std::string> their_version_parts = absl::StrSplit(std::string(their_version), '.');
            const std::vector<std::string> our_version_parts = absl::StrSplit(std::string(our_version), '.');
            compatible = (their_version_parts.size() >= 3) &&
                         (our_version_parts.size() >= 3) &&
                         (their_version_parts[0] == our_version_parts[0]) &&
                         (their_version_parts[1] == our_version_parts[1]) &&
                         (their_version_parts[2] == our_version_parts[2]);
        }
    }
    return compatible;
}

//! Generate log arguments for Silkworm library version
static log::Args log_args_for_version() {
    const auto build_info{silkworm_get_buildinfo()};
    return {
        "git_branch",
        std::string(build_info->git_branch),
        "git_tag",
        std::string(build_info->project_version),
        "git_commit",
        std::string(build_info->git_commit_hash)};
}

//! Generate log arguments for execution flush at specified block
static log::Args log_args_for_exec_flush(const db::Buffer& state_buffer, uint64_t max_batch_size, uint64_t current_block) {
    return {
        "batch",
        std::to_string(state_buffer.current_batch_state_size()),
        "max_batch",
        std::to_string(max_batch_size),
        "block",
        std::to_string(current_block)};
}

//! Generate log arguments for execution commit at specified block
static log::Args log_args_for_exec_commit(StopWatch::Duration elapsed, const std::filesystem::path& db_path) {
    return {
        "in",
        StopWatch::format(elapsed),
        "chaindata",
        std::to_string(Directory{db_path}.size())};
}

static std::filesystem::path make_path(const char data_dir_path[SILKWORM_PATH_SIZE]) {
    // treat as char8_t so that filesystem::path assumes UTF-8 encoding of the input path
    auto begin = reinterpret_cast<const char8_t*>(data_dir_path);
    size_t len = strnlen(data_dir_path, SILKWORM_PATH_SIZE);
    return std::filesystem::path{begin, begin + len};
}

//! Generate log arguments for execution progress at specified block
static log::Args log_args_for_exec_progress(ExecutionProgress& progress, uint64_t current_block) {
    static auto float_to_string = [](float f) -> std::string {
        const auto size = std::snprintf(nullptr, 0, "%.1f", static_cast<double>(f));
        std::string s(static_cast<size_t>(size + 1), '\0');                       // +1 for null terminator
        (void)std::snprintf(s.data(), s.size(), "%.1f", static_cast<double>(f));  // certain to fit
        return s;
    };

    const auto elapsed{progress.end_time - progress.start_time};
    progress.start_time = progress.end_time;
    const auto duration_seconds{std::chrono::duration_cast<std::chrono::seconds>(elapsed)};
    const auto elapsed_seconds = duration_seconds.count() != 0 ? float(duration_seconds.count()) : 1.0f;
    if (progress.processed_blocks == 0) {
        return {"number", std::to_string(current_block), "db", "waiting..."};
    }
    const auto speed_blocks = float(progress.processed_blocks) / elapsed_seconds;
    const auto speed_transactions = float(progress.processed_transactions) / elapsed_seconds;
    const auto speed_mgas = float(progress.processed_gas) / elapsed_seconds / 1'000'000;
    progress.processed_blocks = 0;
    progress.processed_transactions = 0;
    progress.processed_gas = 0;
    std::stringstream progress_stream;
    progress_stream << std::fixed << std::setprecision(2) << progress.gas_state_perc * 100 << "%";
    return {
        "number",
        std::to_string(current_block),
        "blk/s",
        float_to_string(speed_blocks),
        "tx/s",
        float_to_string(speed_transactions),
        "Mgas/s",
        float_to_string(speed_mgas),
        "batchProgress",
        progress_stream.str()};
}

//! A signal handler guard using RAII pattern to acquire/release signal handling
class SignalHandlerGuard {
  public:
    SignalHandlerGuard() { SignalHandler::init(/*custom_handler=*/{}, /*silent=*/true); }
    ~SignalHandlerGuard() { SignalHandler::reset(); }
};

SILKWORM_EXPORT int silkworm_init(
    SilkwormHandle* handle,
    const struct SilkwormSettings* settings) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!settings) {
        return SILKWORM_INVALID_SETTINGS;
    }

    if (!is_compatible_mdbx_version(settings->libmdbx_version, silkworm_libmdbx_version(), MdbxVersionCheck::kExact)) {
        return SILKWORM_INCOMPATIBLE_LIBMDBX;
    }

    static bool is_initialized = false;
    if (is_initialized) {
        return SILKWORM_TOO_MANY_INSTANCES;
    } else {
        is_initialized = true;
    }

    log::init(kLogSettingsLikeErigon);
    log::Info{"Silkworm build info", log_args_for_version()};  // NOLINT(*-unused-raii)

    auto snapshot_repository = std::make_unique<snapshots::SnapshotRepository>();
    db::DataModel::set_snapshot_repository(snapshot_repository.get());

    // NOLINTNEXTLINE(bugprone-unhandled-exception-at-new)
    *handle = new SilkwormInstance{
        {},  // context_pool_settings
        make_path(settings->data_dir_path),
        std::move(snapshot_repository),
        {},  // rpcdaemon unique_ptr
        {},  // sentry_thread unique_ptr
        {},  // sentry_stop_signal
    };
    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_build_recsplit_indexes(SilkwormHandle handle, struct SilkwormMemoryMappedFile* snapshots[], size_t len) SILKWORM_NOEXCEPT {
    const int kNeededIndexesToBuildInParallel = 2;

    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }

    std::vector<std::shared_ptr<snapshots::Index>> needed_indexes;
    for (size_t i = 0; i < len; i++) {
        struct SilkwormMemoryMappedFile* snapshot = snapshots[i];
        if (!snapshot) {
            return SILKWORM_INVALID_SNAPSHOT;
        }
        auto snapshot_region = make_region(*snapshot);

        const auto snapshot_path = snapshots::SnapshotPath::parse(snapshot->file_path);
        if (!snapshot_path) {
            return SILKWORM_INVALID_PATH;
        }

        std::shared_ptr<snapshots::Index> index;
        switch (snapshot_path->type()) {
            case snapshots::SnapshotType::headers: {
                index = std::make_shared<snapshots::HeaderIndex>(*snapshot_path, snapshot_region);
                break;
            }
            case snapshots::SnapshotType::bodies: {
                index = std::make_shared<snapshots::BodyIndex>(*snapshot_path, snapshot_region);
                break;
            }
            case snapshots::SnapshotType::transactions: {
                index = std::make_shared<snapshots::TransactionIndex>(*snapshot_path, snapshot_region);
                break;
            }
            default: {
                SILKWORM_ASSERT(false);
            }
        }
        needed_indexes.push_back(index);
    }

    if (needed_indexes.size() < kNeededIndexesToBuildInParallel) {
        // sequential build
        for (const auto& index : needed_indexes) {
            index->build();
        }
    } else {
        // parallel build
        ThreadPool workers;

        // Create worker tasks for missing indexes
        for (const auto& index : needed_indexes) {
            workers.push_task([=]() {
                try {
                    SILK_INFO << "Build index: " << index->path().filename() << " start";
                    index->build();
                    SILK_INFO << "Build index: " << index->path().filename() << " end";
                } catch (const std::exception& ex) {
                    SILK_CRIT << "Build index: " << index->path().filename() << " failed [" << ex.what() << "]";
                }
            });
        }

        // Wait for all missing indexes to be built or stop request
        while (workers.get_tasks_total()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Wait for any already-started-but-unfinished work in case of stop request
        workers.pause();
        workers.wait_for_tasks();
    }

    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_add_snapshot(SilkwormHandle handle, SilkwormChainSnapshot* snapshot) SILKWORM_NOEXCEPT {
    if (!handle || !handle->snapshot_repository) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!snapshot) {
        return SILKWORM_INVALID_SNAPSHOT;
    }
    const SilkwormHeadersSnapshot& hs = snapshot->headers;
    const auto headers_segment_path = snapshots::SnapshotPath::parse(hs.segment.file_path);
    if (!headers_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshots::MappedHeadersSnapshot mapped_h_snapshot{
        .segment = make_region(hs.segment),
        .header_hash_index = make_region(hs.header_hash_index)};
    auto headers_snapshot = std::make_unique<snapshots::HeaderSnapshot>(*headers_segment_path, mapped_h_snapshot);
    headers_snapshot->reopen_segment();
    headers_snapshot->reopen_index();

    const SilkwormBodiesSnapshot& bs = snapshot->bodies;
    const auto bodies_segment_path = snapshots::SnapshotPath::parse(bs.segment.file_path);
    if (!bodies_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshots::MappedBodiesSnapshot mapped_b_snapshot{
        .segment = make_region(bs.segment),
        .block_num_index = make_region(bs.block_num_index)};
    auto bodies_snapshot = std::make_unique<snapshots::BodySnapshot>(*bodies_segment_path, mapped_b_snapshot);
    bodies_snapshot->reopen_segment();
    bodies_snapshot->reopen_index();

    const SilkwormTransactionsSnapshot& ts = snapshot->transactions;
    const auto transactions_segment_path = snapshots::SnapshotPath::parse(ts.segment.file_path);
    if (!transactions_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshots::MappedTransactionsSnapshot mapped_t_snapshot{
        .segment = make_region(ts.segment),
        .tx_hash_index = make_region(ts.tx_hash_index),
        .tx_hash_2_block_index = make_region(ts.tx_hash_2_block_index)};
    auto transactions_snapshot = std::make_unique<snapshots::TransactionSnapshot>(*transactions_segment_path, mapped_t_snapshot);
    transactions_snapshot->reopen_segment();
    transactions_snapshot->reopen_index();

    snapshots::SnapshotBundle bundle{
        .headers_snapshot_path = *headers_segment_path,
        .headers_snapshot = std::move(headers_snapshot),
        .bodies_snapshot_path = *bodies_segment_path,
        .bodies_snapshot = std::move(bodies_snapshot),
        .tx_snapshot_path = *transactions_segment_path,
        .tx_snapshot = std::move(transactions_snapshot)};
    handle->snapshot_repository->add_snapshot_bundle(std::move(bundle));
    return SILKWORM_OK;
}

SILKWORM_EXPORT const char* silkworm_libmdbx_version() SILKWORM_NOEXCEPT {
    return ::mdbx::get_version().git.describe;
}

SILKWORM_EXPORT int silkworm_start_rpcdaemon(SilkwormHandle handle, MDBX_env* env) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (handle->rpcdaemon) {
        return SILKWORM_SERVICE_ALREADY_STARTED;
    }

    struct EnvUnmanaged : public ::mdbx::env {
        explicit EnvUnmanaged(MDBX_env* ptr) : ::mdbx::env{ptr} {}
    } unmanaged_env{env};

    // TODO(canepat) add RPC options in API and convert them
    rpc::DaemonSettings settings{
        .engine_end_point = "",  // disable end-point for Engine RPC API
        .skip_protocol_check = true,
        .erigon_json_rpc_compatibility = true,
    };

    // Create the one-and-only Silkrpc daemon
    handle->rpcdaemon = std::make_unique<rpc::Daemon>(settings, std::make_optional<mdbx::env>(unmanaged_env));

    // Check protocol version compatibility with Core Services
    if (!settings.skip_protocol_check) {
        SILK_INFO << "[Silkworm RPC] Checking protocol version compatibility with core services...";

        const auto checklist = handle->rpcdaemon->run_checklist();
        for (const auto& protocol_check : checklist.protocol_checklist) {
            SILK_INFO << protocol_check.result;
        }
        checklist.success_or_throw();
    } else {
        SILK_TRACE << "[Silkworm RPC] Skip protocol version compatibility check with core services";
    }

    SILK_INFO << "[Silkworm RPC] Starting ETH API at " << settings.eth_end_point;
    handle->rpcdaemon->start();

    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_stop_rpcdaemon(SilkwormHandle handle) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!handle->rpcdaemon) {
        return SILKWORM_OK;
    }

    handle->rpcdaemon->stop();
    SILK_INFO << "[Silkworm RPC] Exiting...";
    handle->rpcdaemon->join();
    SILK_INFO << "[Silkworm RPC] Stopped";
    handle->rpcdaemon.reset();

    return SILKWORM_OK;
}

class BlockProvider {
    static constexpr size_t kTxnRefreshThreshold{100};

  public:
    BlockProvider(BoundedBuffer<std::optional<Block>>* block_buffer,
                  mdbx::env env,
                  BlockNum start_block, BlockNum max_block)
        : block_buffer_{block_buffer},
          env_{std::move(env)},
          start_block_{start_block},
          max_block_{max_block} {}

    void operator()() {
        db::ROTxnManaged txn{env_};
        db::DataModel access_layer{txn};

        BlockNum current_block{start_block_};
        size_t refresh_counter{kTxnRefreshThreshold};

        while (current_block <= max_block_) {
            Block block;

            const bool success{access_layer.read_block(current_block, /*read_senders=*/true, block)};
            if (!success) {
                block_buffer_->push_front(std::nullopt);
                txn.abort();
                return;
            }
            block_buffer_->push_front(std::move(block));

            if (SignalHandler::signalled()) {
                log::Info{"[4/12 Execution] BlockProvider received signal, stopping"};
                txn.abort();
                return;
            }

            ++current_block;

            if (--refresh_counter == 0) {
                // log::Info{"[4/12 Execution] BlockProvider Refreshing txn"};
                // txn.renew();
                txn.abort();
                txn = db::ROTxnManaged{env_};
                // log::Info{"[4/12 Execution] BlockProvider Refreshed txn"};
                refresh_counter = kTxnRefreshThreshold;
            }
        }
    }

  private:
    BoundedBuffer<std::optional<Block>>* block_buffer_;
    mdbx::env env_;
    BlockNum start_block_;
    BlockNum max_block_;
};

class ChangeSetWriter {
  public:
    ChangeSetWriter(BoundedBuffer<std::optional<db::BufferChangeset>>* changeset_buffer, mdbx::env env)
        : changeset_buffer_{changeset_buffer},
          env_{std::move(env)} {}

    void operator()() {
        db::RWTxnManaged txn{env_};
        while (true) {
            std::optional<db::BufferChangeset> changeset;
            changeset_buffer_->pop_back(&changeset);

            if (SignalHandler::signalled()) {
                log::Info{"[4/12 Execution] ChangeSetWriter received signal, stopping"};
                txn.abort();
                return;
            }

            // empty changeset signals termination
            if (!changeset) {
                txn.commit_and_stop();
                return;
            }

            auto tmp = changeset.value();

            db::Buffer state_buffer{txn, /*prune_history_threshold=*/0, tmp, std::nullopt};
            state_buffer.write_history_to_db(txn);

            if (changeset->block_account_changes.size() > 1 || changeset->block_storage_changes.size() > 1) {
                log::Info{"[4/12 Execution] ChangeSetWriter received changeset",
                          {"account", std::to_string(changeset->block_account_changes.size()),
                           "storage", std::to_string(changeset->block_storage_changes.size()),
                           "receipts", std::to_string(changeset->receipts.size()),
                           "logs", std::to_string(changeset->logs.size()),
                           "call_traces", std::to_string(changeset->call_traces.size())}};
            }
        }
    }

  private:
    BoundedBuffer<std::optional<db::BufferChangeset>>* changeset_buffer_;
    mdbx::env env_;
};

SILKWORM_EXPORT
int silkworm_execute_blocks(SilkwormHandle handle, MDBX_txn* mdbx_txn, uint64_t chain_id, uint64_t start_block, uint64_t max_block,
                            uint64_t batch_size, bool write_change_sets, bool write_receipts, bool write_call_traces,
                            uint64_t* last_executed_block, int* mdbx_error_code) SILKWORM_NOEXCEPT {
    log::Info{"[4/12 Execution] Executing blocks called",  // NOLINT(*-unused-raii)
              log::Args{"start", std::to_string(start_block), "end", std::to_string(max_block),
                        "write_change_sets",
                        std::to_string(write_change_sets),
                        "write_receipts",
                        std::to_string(write_receipts),
                        "write_call_traces",
                        std::to_string(write_call_traces)}};

    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!mdbx_txn) {
        return SILKWORM_INVALID_MDBX_TXN;
    }
    if (start_block > max_block) {
        return SILKWORM_INVALID_BLOCK_RANGE;
    }
    const auto chain_info = kKnownChainConfigs.find(chain_id);
    if (!chain_info) {
        return SILKWORM_UNKNOWN_CHAIN_ID;
    }
    const ChainConfig* chain_config{*chain_info};

    SignalHandlerGuard signal_guard;
    try {
        // Wrap MDBX txn into an internal *unmanaged* txn, i.e. MDBX txn is only used but neither aborted nor committed

        db::RWTxnUnmanaged external_txn{mdbx_txn};
        auto db_env = external_txn.db();
        auto db_env2 = external_txn.db();
        auto db_env3 = external_txn.db();
        auto db_env4 = external_txn.db();
        external_txn.commit_and_stop();

        db::ROTxnManaged txn_ro{db_env};

        db::Buffer state_buffer{txn_ro, /*prune_history_threshold=*/0};
        BoundedBuffer<std::optional<Block>> buffer1_preloaded_block{kMaxBlockBufferSize};
        BoundedBuffer<std::optional<db::BufferChangeset>> buffer4_changeset{kMaxBlockBufferSize};
        BlockProvider block_provider{&buffer1_preloaded_block, db_env3, start_block, max_block};
        std::thread block_provider_thread(block_provider);

        static constexpr size_t kCacheSize{5'000};
        AnalysisCache analysis_cache{kCacheSize};
        ObjectPool<evmone::ExecutionState> state_pool;

        const size_t max_batch_size{batch_size / 10};

        // Transform batch size limit into gas units (Ggas = Giga gas)
        const size_t gas_max_batch_size{(batch_size / 10) * 2_Kibi};  // 256MB -> 512Ggas roughly

        ExecutionProgress progress{.start_time = std::chrono::steady_clock::now()};
        auto signal_check_time{progress.start_time};
        auto log_time{progress.start_time + 20s};

        size_t gas_batch_size{0};

        std::optional<Block> block;

        const auto protocol_rule_set{protocol::rule_set_factory(*chain_config)};
        if (!protocol_rule_set) {
            return SILKWORM_UNKNOWN_CHAIN_ID;
        }

        BlockNum block_number{start_block};
        while (block_number <= max_block) {
            std::thread changeset_writer_thread(ChangeSetWriter{&buffer4_changeset, db_env4});

            while (block_number <= max_block && state_buffer.current_batch_state_size() < max_batch_size) {
                // log::Info{"[4/12 Execution] Processing block",  // NOLINT(*-unused-raii)
                //           {"block number", std::to_string(block_number)}};

                buffer1_preloaded_block.pop_back(&block);
                if (!block) {
                    block_provider_thread.detach();
                    return SILKWORM_BLOCK_NOT_FOUND;
                }

                ExecutionProcessor processor{*block, *protocol_rule_set, state_buffer, *chain_config};
                processor.evm().analysis_cache = &analysis_cache;
                processor.evm().state_pool = &state_pool;
                CallTraces traces;
                CallTracer tracer{traces};
                if (write_call_traces) {
                    processor.evm().add_tracer(tracer);
                }

                std::vector<Receipt> receipts;
                const auto result{processor.execute_and_write_block(receipts)};
                if (result != ValidationResult::kOk) {
                    return SILKWORM_INVALID_BLOCK;
                }

                if (write_receipts) {
                    state_buffer.insert_receipts(block->header.number, receipts);
                }
                if (write_call_traces) {
                    state_buffer.insert_call_traces(block->header.number, traces);
                }

                if (last_executed_block) {
                    *last_executed_block = block->header.number;
                }

                ++progress.processed_blocks;
                progress.processed_transactions += block->transactions.size();
                progress.processed_gas += block->header.gas_used;
                gas_batch_size += block->header.gas_used;

                // Always flush history for single processed block (no batching)
                // state_buffer.write_history_to_db(txn_rw, write_change_sets);
                db::BufferChangeset changeset;
                state_buffer.extract_changeset(changeset);
                if (changeset.block_account_changes.size() > 1 || changeset.block_storage_changes.size() > 1) {
                    log::Info{"[4/12 Execution] Extracted changeset",
                              {"account", std::to_string(changeset.block_account_changes.size()),
                               "storage", std::to_string(changeset.block_storage_changes.size())}};
                }
                buffer4_changeset.push_front(std::move(changeset));

                const auto now{std::chrono::steady_clock::now()};
                if (signal_check_time <= now) {
                    if (SignalHandler::signalled()) {
                        log::Info{"[4/12 Execution] Signal received, stopping1"};
                        block_provider_thread.join();
                        log::Info{"[4/12 Execution] Signal received, stopping2"};
                        buffer4_changeset.push_front(std::nullopt);
                        log::Info{"[4/12 Execution] Signal received, stopping3"};
                        changeset_writer_thread.join();
                        log::Info{"[4/12 Execution] Signal received, stopping4"};
                        txn_ro.abort();
                        log::Info{"[4/12 Execution] Signal received, stopping5"};
                        external_txn.renew(db_env);
                        log::Info{"[4/12 Execution] Signal received, stopping6"};

                        log::Info{"[4/12 Execution] Terminated by signal"};
                        return SILKWORM_TERMINATION_SIGNAL;
                    }
                    signal_check_time = now + 5s;
                }
                if (log_time <= now) {
                    progress.gas_state_perc = float(gas_batch_size) / float(gas_max_batch_size);
                    progress.end_time = now;
                    log::Info{"[4/12 Execution] Executed blocks",  // NOLINT(*-unused-raii)
                              log_args_for_exec_progress(progress, block->header.number)};
                    log_time = now + 20s;
                }

                ++block_number;
            }

            // Flush state buffer if we've reached the target batch size
            log::Info{"[4/12 Execution] Flushing state",  // NOLINT(*-unused-raii)
                      log_args_for_exec_flush(state_buffer, max_batch_size, block->header.number)};
            StopWatch sw{/*auto_start=*/true};

            // log::Info{"step A"};
            buffer4_changeset.push_front(std::nullopt);  // send terminate signal
            // log::Info{"step B"};
            changeset_writer_thread.join();

            // log::Info{"step 1"};
            txn_ro.abort();
            // log::Info{"step 2"};
            db::RWTxnManaged txn_rw{db_env2};
            // log::Info{"step 3"};
            state_buffer.write_state_to_db(txn_rw);
            // log::Info{"step 4"};
            txn_rw.commit_and_stop();
            // log::Info{"step 5"};
            txn_ro.renew(db_env);
            // log::Info{"step 6"};
            gas_batch_size = 0;
            const auto [elapsed, _]{sw.stop()};
            log::Info("[4/12 Execution] Commit state+history",  // NOLINT(*-unused-raii)
                      log_args_for_exec_commit(sw.since_start(elapsed), db_env.get_path()));
        }

        block_provider_thread.join();

        external_txn.renew(db_env);

        return SILKWORM_OK;

    } catch (const mdbx::exception& e) {
        if (mdbx_error_code) {
            *mdbx_error_code = e.error().code();
        }
        log::Error{"[4/12 Execution] mdbx::exception"};
        SILK_ERROR << "mdbx::exception exception " << e.what();
        return SILKWORM_MDBX_ERROR;
    } catch (const DecodingError&) {
        log::Error{"[4/12 Execution] DecodingError"};
        SILK_ERROR << "DecodingError exception ";
        return SILKWORM_DECODING_ERROR;
    } catch (const std::exception& e) {
        log::Error{"[4/12 Execution] std::exception"};
        SILK_ERROR << "exception: " << e.what();
        return SILKWORM_INTERNAL_ERROR;
    } catch (...) {
        log::Error{"[4/12 Execution] unknown exception"};
        SILK_ERROR << "unknown exception";
        return SILKWORM_UNKNOWN_ERROR;
    }
}

SILKWORM_EXPORT int silkworm_fini(SilkwormHandle handle) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!handle->snapshot_repository) {
        return SILKWORM_INVALID_HANDLE;
    }
    delete handle;
    return SILKWORM_OK;
}
