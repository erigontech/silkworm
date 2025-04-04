// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <map>
#include <ranges>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>

#include <CLI/CLI.hpp>
#include <boost/format.hpp>
#include <gsl/util>
#include <magic_enum.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <silkworm/core/trie/prefix_set.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/chain_data_init.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/snapshot_sync.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/cli/common.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>
#include <silkworm/node/stagedsync/stages/stage_bodies.hpp>
#include <silkworm/node/stagedsync/stages/stage_interhashes/trie_cursor.hpp>
#include <silkworm/node/stagedsync/stages_factory_impl.hpp>

namespace fs = std::filesystem;
using namespace silkworm;
using namespace silkworm::datastore;

class Progress {
  public:
    explicit Progress(uint32_t width) : bar_width_{width}, percent_step_{100u / width} {};
    ~Progress() = default;

    //! Returns current progress percent
    uint32_t percent() const {
        if (!max_counter_) {
            return 100;
        }
        if (!current_counter_) {
            return 0;
        }
        return static_cast<uint32_t>(current_counter_ * 100 / max_counter_);
    }

    void step() { ++current_counter_; }
    void set_current(size_t count) { current_counter_ = std::max(count, current_counter_); }
    size_t get_current() const noexcept { return current_counter_; }
    size_t get_increment_count() const noexcept { return bar_width_ ? (max_counter_ / bar_width_) : 0u; }

    void reset() {
        current_counter_ = 0;
        printed_bar_len_ = 0;
    }
    void set_task_count(size_t iterations) {
        reset();
        max_counter_ = iterations;
    }

    //! Prints progress ticks
    std::string print_interval(char c = '.') {
        uint32_t percentage{std::min(percent(), 100u)};
        uint32_t num_chars{percentage / percent_step_};
        if (!num_chars) return "";
        uint32_t int_chars{num_chars - printed_bar_len_};
        if (!int_chars) return "";
        std::string ret(int_chars, c);
        printed_bar_len_ += int_chars;
        return ret;
    }

    [[maybe_unused]] std::string print_progress(char c = '.') const {
        uint32_t percentage{percent()};
        uint32_t num_chars{percentage / percent_step_};
        if (!num_chars) {
            return "";
        }
        std::string ret(num_chars, c);
        return ret;
    }

  private:
    uint32_t bar_width_;
    uint32_t percent_step_;
    size_t max_counter_{0};
    size_t current_counter_{0};
    uint32_t printed_bar_len_{0};
};

void cursor_for_each(::mdbx::cursor& cursor, kvdb::WalkFuncRef walker) {
    auto data = cursor.eof() ? cursor.to_first(/*throw_notfound=*/false) : cursor.current(/*throw_notfound=*/false);
    while (data) {
        walker(kvdb::from_slice(data.key), kvdb::from_slice(data.value));
        data = cursor.move(mdbx::cursor::move_operation::next, /*throw_notfound=*/false);
    }
}

bool user_confirmation(const std::string& message = {"Confirm ?"}) {
    static std::regex pattern{"^([yY])?([nN])?$"};
    std::smatch matches;

    std::string user_input;
    do {
        std::cout << "\n"
                  << message << " [y/N] ";
        std::cin >> user_input;
        std::cin.clear();
        if (std::regex_search(user_input, matches, pattern, std::regex_constants::match_default)) {
            break;
        }
        std::cout << "Unexpected user input: " << user_input << "\n";
    } while (true);

    return matches[2].length() == 0;
}

//! Comparison for stage names according to the forward stage order
struct StageOrderCompare {
    bool operator()(const std::string& lhs, const std::string& rhs) const {
        static const auto kStagesForwardOrder = fix_stages_forward_order();
        const auto lhs_it = std::ranges::find(kStagesForwardOrder, lhs);
        const auto rhs_it = std::ranges::find(kStagesForwardOrder, rhs);
        if (lhs_it == kStagesForwardOrder.end() && rhs_it == kStagesForwardOrder.end()) {
            return lhs < rhs;
        }
        return lhs_it < rhs_it;
    }

  private:
    static stagedsync::ExecutionPipeline::StageNames fix_stages_forward_order() {
        auto stages_forward_order = stagedsync::ExecutionPipeline::stages_forward_order();
        add_after_history_index(stages_forward_order, db::stages::kStorageHistoryIndexKey);
        add_after_history_index(stages_forward_order, db::stages::kAccountHistoryIndexKey);
        return stages_forward_order;
    }
    static void add_after_history_index(stagedsync::ExecutionPipeline::StageNames& forward_stages, const char* stage) {
        auto history_index_it = std::ranges::find(forward_stages, db::stages::kHistoryIndexKey);
        forward_stages.insert(std::next(history_index_it), stage);
    }
};

void list_stages(const kvdb::EnvConfig& config) {
    static constexpr char kTableHeaderFormat[] = " %-26s %10s ";
    static constexpr char kTableRowFormat[] = " %-26s %10u %-8s";

    auto env = kvdb::open_env(config);
    auto txn = env.start_read();
    if (!kvdb::has_map(txn, db::table::kSyncStageProgress.name)) {
        throw std::runtime_error("Either not a Silkworm db or table " +
                                 std::string{db::table::kSyncStageProgress.name} + " not found");
    }

    auto stage_cursor = open_cursor(txn, db::table::kSyncStageProgress);
    if (txn.get_map_stat(stage_cursor.map()).ms_entries) {
        std::map<std::string, BlockNum, StageOrderCompare> stage_height_by_name;
        auto result = stage_cursor.to_first(/*throw_notfound =*/false);
        while (result.done) {
            std::string name{result.key.string_view()};
            const size_t height = endian::load_big_u64(static_cast<uint8_t*>(result.value.data()));
            stage_height_by_name.insert_or_assign(std::move(name), height);
            result = stage_cursor.to_next(/*throw_notfound =*/false);
        }

        std::cout << "\n"
                  << (boost::format(kTableHeaderFormat) % "Stage Name" % "Block") << "\n";
        std::cout << (boost::format(kTableHeaderFormat) % std::string(26, '-') % std::string(10, '-')) << "\n";

        for (const auto& [stage_name, stage_height] : stage_height_by_name) {
            // Handle "prune_" stages
            static constexpr std::string_view kPrunePrefix{"prune_"};
            size_t offset{0};
            if (std::memcmp(stage_name.data(), kPrunePrefix.data(), kPrunePrefix.size()) == 0) {
                offset = kPrunePrefix.size();
            }
            const bool known = db::stages::is_known_stage(stage_name.data() + offset);
            std::cout << (boost::format(kTableRowFormat) % stage_name % stage_height %
                          (known ? std::string(8, ' ') : "Unknown"))
                      << "\n";
        }
        std::cout << "\n\n";
    } else {
        std::cout << "\n There are no stages to list\n\n";
    }

    txn.abort();
    env.close(config.shared);
}

void set_stage_progress(kvdb::EnvConfig& config, const std::string& stage_name, uint32_t new_height, bool dry) {
    config.readonly = false;

    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{kvdb::open_env(config)};
    kvdb::RWTxnManaged txn{env};
    if (!db::stages::is_known_stage(stage_name.c_str())) {
        throw std::runtime_error("Stage name " + stage_name + " is not known");
    }
    if (!has_map(txn, db::table::kSyncStageProgress.name)) {
        throw std::runtime_error("Either non Silkworm db or table " +
                                 std::string(db::table::kSyncStageProgress.name) + " not found");
    }
    auto old_height{db::stages::read_stage_progress(txn, stage_name.c_str())};
    db::stages::write_stage_progress(txn, stage_name.c_str(), new_height);
    if (!dry) {
        txn.commit_and_renew();
    }

    std::cout << "\n Stage " << stage_name << " touched from " << old_height << " to " << new_height << "\n\n";
}

static stagedsync::BodiesStageFactory make_bodies_stage_factory(
    const ChainConfig& chain_config,
    db::DataModelFactory data_model_factory) {
    return [&chain_config, data_model_factory = std::move(data_model_factory)](stagedsync::SyncContext* sync_context) {
        return std::make_unique<stagedsync::BodiesStage>(
            sync_context,
            chain_config,
            data_model_factory,
            [] { return 0; });
    };
}

static stagedsync::StageContainerFactory make_stages_factory(
    const NodeSettings& node_settings,
    db::DataModelFactory data_model_factory) {
    auto bodies_stage_factory = make_bodies_stage_factory(*node_settings.chain_config, data_model_factory);
    return stagedsync::StagesFactoryImpl::to_factory({
        node_settings,
        std::move(data_model_factory),
        std::move(bodies_stage_factory),
    });
}

void debug_unwind(kvdb::EnvConfig& config, std::unique_ptr<DataDirectory>&& data_directory, BlockNum height, uint32_t step,
                  const bool dry, const bool force, const std::string& start_at_stage, const std::string& stop_before_stage) {
    ensure(config.exclusive, "Function requires exclusive access to database");
    ensure(height > 0, "Function requires non-zero height block");

    config.readonly = false;

    const auto datadir_path = std::filesystem::path{config.path}.parent_path();
    SILK_INFO << "Debug unwind datadir: " << datadir_path.string();

    Environment::set_stop_at_block(height);
    Environment::set_start_at_stage(start_at_stage);
    Environment::set_stop_before_stage(stop_before_stage);

    db::DataStore data_store{config, data_directory->snapshots().path()};

    kvdb::ROTxnManaged ro_txn = data_store.chaindata().access_ro().start_ro_tx();
    const auto chain_config = db::read_chain_config(ro_txn);
    ensure(chain_config.has_value(), "Uninitialized Silkworm db or unknown/custom chain");
    ro_txn.abort();

    db::DataModelFactory data_model_factory{data_store.ref()};

    // We need full snapshot sync to take place to have database tables properly updated
    snapshots::SnapshotSettings snapshot_settings{
        .no_downloader = true,  // do not download snapshots
        .stop_freezer = true,   // do not generate new snapshots
        .no_seeding = true,     // do not seed existing snapshots
    };
    struct EmptyStageScheduler : public datastore::StageScheduler {
        Task<void> schedule(std::function<void(db::RWTxn&)> /*callback*/) override { co_return; }
    };
    EmptyStageScheduler empty_scheduler;
    db::SnapshotSync snapshot_sync{
        std::move(snapshot_settings),
        chain_config->chain_id,
        data_store.ref(),
        std::filesystem::path{},
        empty_scheduler};

    boost::asio::io_context io_context;
    std::thread ioc_thread{[&]() {
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        io_context.run();
    }};
    auto _ = gsl::finally([&]() {
        io_context.stop();
        ioc_thread.join();
    });
    auto snap_sync_future = concurrency::spawn_future(io_context.get_executor(), snapshot_sync.run());
    snap_sync_future.get();

    // Commit is enabled by default in RWTxn(Managed), so we need to check here
    kvdb::RWTxnManaged txn = data_store.chaindata().access_rw().start_rw_tx();
    if (dry) {
        txn.disable_commit();
    } else {
        if (!force && !user_confirmation("Are you sure? This will apply the changes to the database!")) {
            return;
        }
        txn.enable_commit();  // this doesn't harm and works even if default changes
    }

    // We should have all the blocks in the interval already validated by stages Headers+Bodies
    const auto headers_progress = db::stages::read_stage_progress(txn, db::stages::kHeadersKey);
    ensure(headers_progress >= height, [&]() { return "Insufficient Headers progress: " + std::to_string(headers_progress); });
    const auto bodies_progress = db::stages::read_stage_progress(txn, db::stages::kBlockBodiesKey);
    ensure(bodies_progress >= height, [&]() { return "Insufficient Bodies progress: " + std::to_string(bodies_progress); });

    NodeSettings settings{
        .data_directory = std::move(data_directory),
        .chaindata_env_config = config,
        .chain_config = chain_config};

    // Start timer scheduler thread to observe stage progress during processing
    stagedsync::TimerFactory log_timer_factory = [&](std::function<bool()> callback) {
        return std::make_shared<Timer>(io_context.get_executor(), settings.sync_loop_log_interval_seconds * 1000, std::move(callback));
    };

    stagedsync::ExecutionPipeline stage_pipeline{
        data_model_factory,
        std::move(log_timer_factory),
        make_stages_factory(settings, data_model_factory),
    };

    const auto forward_target = height;
    SILK_INFO << "Debug unwind: forward to=" << forward_target << " START";
    const auto forward_result = stage_pipeline.forward(txn, forward_target);
    SILK_INFO << "Debug unwind: forward to=" << forward_target << " END";
    ensure(forward_result == stagedsync::Stage::Result::kStoppedByEnv,
           [&]() { return "Debug unwind: forward failed " + std::string{magic_enum::enum_name(forward_result)}; });

    const auto unwind_point = height - step;
    SILK_INFO << "Debug unwind: unwind down to block=" << unwind_point << " START";
    const auto unwind_result = stage_pipeline.unwind(txn, unwind_point);
    ensure(unwind_result == stagedsync::Stage::Result::kSuccess,
           [&]() { return "unwind failed: " + std::string{magic_enum::enum_name(unwind_result)}; });
    SILK_INFO << "Debug unwind: unwind down to block=" << unwind_point << " END";
    SILK_INFO << "Debug unwind: forward+unwind success up to block=" << height;

    // Unwind has just set progress for pre-Execution stages back to unwind_point even if it is within the snapshots
    // We need to reset progress for such stages to the max block in snapshots to avoid database update on next start
    auto& blocks_repository = data_store.blocks_repository();
    db::stages::write_stage_progress(txn, db::stages::kHeadersKey, blocks_repository.max_timestamp_available());
    db::stages::write_stage_progress(txn, db::stages::kBlockBodiesKey, blocks_repository.max_timestamp_available());
    db::stages::write_stage_progress(txn, db::stages::kBlockHashesKey, blocks_repository.max_timestamp_available());
    db::stages::write_stage_progress(txn, db::stages::kSendersKey, blocks_repository.max_timestamp_available());

    txn.commit_and_stop();
}

void unwind(kvdb::EnvConfig& config, std::unique_ptr<DataDirectory>&& data_directory,
            BlockNum unwind_point, const bool remove_blocks, const bool dry) {
    ensure(config.exclusive, "Function requires exclusive access to database");

    config.readonly = false;

    db::DataStore data_store{config, data_directory->snapshots().path()};

    kvdb::RWTxnManaged txn = data_store.chaindata().access_rw().start_rw_tx();

    // Commit is enabled by default in RWTxn(Managed), so we need to check here
    if (dry) {
        txn.disable_commit();
    } else {
        if (!user_confirmation("Are you sure? This will apply the unwind changes to the database!")) {
            return;
        }
        txn.enable_commit();  // this doesn't harm and works even if default changes
    }

    const auto chain_config = db::read_chain_config(txn);
    ensure(chain_config.has_value(), "Not an initialized Silkworm db or unknown/custom chain");

    db::DataModelFactory data_model_factory{data_store.ref()};

    boost::asio::io_context io_context;

    NodeSettings settings{
        .data_directory = std::move(data_directory),
        .chaindata_env_config = config,
        .chain_config = chain_config};

    stagedsync::TimerFactory log_timer_factory = [&](std::function<bool()> callback) {
        return std::make_shared<Timer>(io_context.get_executor(), settings.sync_loop_log_interval_seconds * 1000, std::move(callback));
    };
    std::thread ioc_thread{[&]() {
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        io_context.run();
    }};
    auto _ = gsl::finally([&]() {
        io_context.stop();
        ioc_thread.join();
    });

    stagedsync::ExecutionPipeline stage_pipeline{
        data_model_factory,
        std::move(log_timer_factory),
        make_stages_factory(settings, data_model_factory),
    };
    const auto unwind_result = stage_pipeline.unwind(txn, unwind_point);

    ensure(unwind_result == stagedsync::Stage::Result::kSuccess,
           [&]() { return "unwind failed: " + std::string{magic_enum::enum_name(unwind_result)}; });

    std::cout << "\n Staged pipeline unwind up to block: " << unwind_point << " completed\n";

    // In consensus-separated Sync/Execution design block headers and bodies are stored by the Sync component
    // not by the Execution component: hence, ExecutionPipeline will not remove them during unwind phase
    if (remove_blocks) {
        std::cout << " Removing also block headers and bodies up to block: " << unwind_point << "\n";

        // Remove the block bodies up to the unwind point
        const auto body_cursor{txn.rw_cursor(db::table::kBlockBodies)};
        const auto start_key{db::block_key(unwind_point + 1)};
        std::size_t erased_bodies{0};
        auto body_data{body_cursor->lower_bound(kvdb::to_slice(start_key), /*throw_notfound=*/false)};
        while (body_data) {
            body_cursor->erase();
            ++erased_bodies;
            body_data = body_cursor->to_next(/*throw_notfound=*/false);
        }
        std::cout << " Removed block bodies erased: " << erased_bodies << "\n";

        // Remove the block headers up to the unwind point
        const auto header_cursor{txn.rw_cursor(db::table::kHeaders)};
        std::size_t erased_headers{0};
        auto header_data{header_cursor->lower_bound(kvdb::to_slice(start_key), /*throw_notfound=*/false)};
        while (header_data) {
            header_cursor->erase();
            ++erased_headers;
            header_data = header_cursor->to_next(/*throw_notfound=*/false);
        }
        std::cout << " Removed block headers erased: " << erased_headers << "\n";

        // Remove the canonical hashes up to the unwind point
        const auto canonical_cursor{txn.rw_cursor(db::table::kCanonicalHashes)};
        std::size_t erased_hashes{0};
        auto hash_data{canonical_cursor->lower_bound(kvdb::to_slice(start_key), /*throw_notfound=*/false)};
        while (hash_data) {
            canonical_cursor->erase();
            ++erased_hashes;
            hash_data = canonical_cursor->to_next(/*throw_notfound=*/false);
        }
        std::cout << " Removed canonical hashes erased: " << erased_hashes << "\n";

        txn.commit_and_stop();
    }
}

void forward(kvdb::EnvConfig& config, std::unique_ptr<DataDirectory>&& data_directory, BlockNum forward_point,
             const bool dry, const std::string& start_at_stage, const std::string& stop_before_stage) {
    ensure(config.exclusive, "Function requires exclusive access to database");

    config.readonly = false;

    Environment::set_stop_at_block(forward_point);
    Environment::set_start_at_stage(start_at_stage);
    Environment::set_stop_before_stage(stop_before_stage);

    db::DataStore data_store{config, data_directory->snapshots().path()};

    kvdb::RWTxnManaged txn = data_store.chaindata().access_rw().start_rw_tx();

    // Commit is enabled by default in RWTxn(Managed), so we need to check here
    if (dry) {
        txn.disable_commit();
    } else {
        if (!user_confirmation("Are you sure? This will apply the changes to the database!")) {
            return;
        }
        txn.enable_commit();  // this doesn't harm and works even if default changes
    }

    const auto chain_config{db::read_chain_config(txn)};
    ensure(chain_config.has_value(), "Uninitialized Silkworm db or unknown/custom chain");

    const auto datadir_path = std::filesystem::path{config.path}.parent_path();
    SILK_INFO << "Forward: datadir=" << datadir_path.string();

    db::DataModelFactory data_model_factory{data_store.ref()};

    boost::asio::io_context io_context;

    NodeSettings settings{
        .data_directory = std::move(data_directory),
        .chaindata_env_config = config,
        .chain_config = chain_config};

    // Start timer scheduler thread to observe stage progress during processing
    stagedsync::TimerFactory log_timer_factory = [&](std::function<bool()> callback) {
        return std::make_shared<Timer>(io_context.get_executor(), settings.sync_loop_log_interval_seconds * 1000, std::move(callback));
    };
    std::thread ioc_thread{[&]() {
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        io_context.run();
    }};
    auto _ = gsl::finally([&]() {
        io_context.stop();
        ioc_thread.join();
    });

    stagedsync::ExecutionPipeline stage_pipeline{
        data_model_factory,
        std::move(log_timer_factory),
        make_stages_factory(settings, data_model_factory),
    };

    const auto forward_result = stage_pipeline.forward(txn, forward_point);
    ensure(forward_result == stagedsync::Stage::Result::kSuccess,
           [&]() { return "forward failed: " + std::string{magic_enum::enum_name(forward_result)}; });

    std::cout << "\n Staged pipeline forward up to block: " << forward_point << " completed\n";
}

void bisect_pipeline(kvdb::EnvConfig& config, BlockNum start, BlockNum end, const bool dry,
                     const std::string& start_at_stage, const std::string& stop_before_stage) {
    ensure(config.exclusive, "Function requires exclusive access to database");
    ensure(start > 0, "Function requires non-zero start block");
    ensure(end >= start, "Function requires valid block interval: end must be greater than or equal to start");

    config.readonly = false;

    Environment::set_stop_at_block(end);
    Environment::set_start_at_stage(start_at_stage);
    Environment::set_stop_before_stage(stop_before_stage);

    auto data_directory = std::make_unique<DataDirectory>();
    db::DataStore data_store{config, data_directory->snapshots().path()};

    kvdb::RWTxnManaged txn = data_store.chaindata().access_rw().start_rw_tx();

    // Commit is enabled by default in RWTxn(Managed), so we need to check here
    if (dry) {
        txn.disable_commit();
    } else {
        if (!user_confirmation("Are you sure? This will apply the changes to the database!")) {
            return;
        }
        txn.enable_commit();  // this doesn't harm and works even if default changes
    }

    const auto chain_config{db::read_chain_config(txn)};
    ensure(chain_config.has_value(), "Uninitialized Silkworm db or unknown/custom chain");

    const auto datadir_path = std::filesystem::path{config.path}.parent_path();
    SILK_INFO << "Bisect: datadir=" << datadir_path.string();

    db::DataModelFactory data_model_factory{data_store.ref()};

    boost::asio::io_context io_context;

    NodeSettings settings{
        .data_directory = std::move(data_directory),
        .chaindata_env_config = config,
        .chain_config = chain_config};

    // Start timer scheduler thread to observe stage progress during processing
    stagedsync::TimerFactory log_timer_factory = [&](std::function<bool()> callback) {
        return std::make_shared<Timer>(io_context.get_executor(), settings.sync_loop_log_interval_seconds * 1000, std::move(callback));
    };
    std::thread ioc_thread{[&]() {
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        io_context.run();
    }};
    auto _ = gsl::finally([&]() {
        io_context.stop();
        ioc_thread.join();
    });

    stagedsync::ExecutionPipeline stage_pipeline{
        data_model_factory,
        std::move(log_timer_factory),
        make_stages_factory(settings, data_model_factory),
    };

    // Unwind staged pipeline down to the previous block wrt start
    const auto initial_unwind_point = start - 1;
    SILK_INFO << "Bisect: unwind down to block=" << initial_unwind_point << " START";
    const auto first_unwind_result = stage_pipeline.unwind(txn, initial_unwind_point);
    ensure(first_unwind_result == stagedsync::Stage::Result::kSuccess,
           [&]() { return "unwind failed: " + std::string{magic_enum::enum_name(first_unwind_result)}; });
    SILK_INFO << "Bisect: unwind down to block=" << initial_unwind_point << " END";

    BlockNum left_point = start, right_point = end;
    std::optional<BlockNum> first_broken_point;
    while (left_point < right_point) {
        Environment::set_stop_at_block(right_point);
        const uint64_t median_point = (left_point + right_point) >> 1;
        SILK_INFO << "Bisect: forward from=" << left_point << " to=" << right_point << " START";
        const auto forward_result = stage_pipeline.forward(txn, right_point);
        SILK_INFO << "Bisect: forward from=" << left_point << " to=" << right_point << " END";
        if (forward_result == stagedsync::Stage::Result::kSuccess || forward_result == stagedsync::Stage::Result::kStoppedByEnv) {
            left_point = right_point;
            if (right_point < end) {
                right_point = (right_point + first_broken_point.value_or(end)) >> 1;
            }
        } else if (stage_pipeline.unwind_point()) {
            first_broken_point = right_point;
            SILK_INFO << "Bisect: first_broken_point=" << *first_broken_point << " median=" << median_point;
            const auto unwind_point = *stage_pipeline.unwind_point();
            SILK_INFO << "Bisect: unwind down to block=" << unwind_point << " START";
            const auto unwind_result = stage_pipeline.unwind(txn, unwind_point);
            ensure(unwind_result == stagedsync::Stage::Result::kSuccess,
                   [&]() { return "unwind failed: " + std::string{magic_enum::enum_name(unwind_result)}; });
            SILK_INFO << "Bisect: unwind down to block=" << unwind_point << " END";
            right_point = unwind_point;
        } else {
            if (forward_result != stagedsync::Stage::Result::kAborted) {
                SILK_ERROR << "Bisect: unexpected forward failure w/o unwind point: " << magic_enum::enum_name(forward_result);
            }
            break;
        }
    }

    if (left_point == end && right_point == end) {
        SILK_INFO << "Bisect: success at block=" << right_point;
    } else {
        SILKWORM_ASSERT(first_broken_point);
        SILK_INFO << "Bisect: failed at block=" << first_broken_point.value();
    }
}

void reset_to_download(const kvdb::EnvConfig& config, const bool keep_senders, const bool force) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    if (!force && !user_confirmation("Are you sure? This will erase the database content written after " +
                                     std::string(keep_senders ? db::stages::kSendersKey : db::stages::kBlockHashesKey) + " stage!")) {
        return;
    }

    auto env{kvdb::open_env(config)};
    kvdb::RWTxnManaged txn(env);

    StopWatch sw(/*auto_start=*/true);
    // Void finish stage
    db::stages::write_stage_progress(txn, db::stages::kFinishKey, 0);
    txn.commit_and_renew();
    SILK_INFO_M(db::stages::kFinishKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void TxLookup stage
    SILK_INFO_M(db::stages::kTxLookupKey, {"table", db::table::kTxLookup.name}) << "truncating ...";
    kvdb::PooledCursor source(*txn, db::table::kTxLookup);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kTxLookupKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kTxLookupKey, 0);
    txn.commit_and_renew();
    SILK_INFO_M(db::stages::kTxLookupKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void CallTraces stage
    SILK_INFO_M(db::stages::kCallTracesKey, {"table", db::table::kCallFromIndex.name}) << "truncating ...";
    source.bind(*txn, db::table::kCallFromIndex);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kCallTracesKey, {"table", db::table::kCallToIndex.name}) << "truncating ...";
    source.bind(*txn, db::table::kCallToIndex);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kCallTracesKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kCallTracesKey, 0);
    txn.commit_and_renew();
    SILK_INFO_M(db::stages::kCallTracesKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void LogIndex stage
    SILK_INFO_M(db::stages::kLogIndexKey, {"table", db::table::kLogTopicIndex.name}) << "truncating ...";
    source.bind(*txn, db::table::kLogTopicIndex);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kLogIndexKey, {"table", db::table::kLogAddressIndex.name}) << "truncating ...";
    source.bind(*txn, db::table::kLogAddressIndex);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kLogIndexKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kLogIndexKey, 0);
    txn.commit_and_renew();
    SILK_INFO_M(db::stages::kLogIndexKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void HistoryIndex (StorageHistoryIndex + AccountHistoryIndex) stage
    SILK_INFO_M(db::stages::kStorageHistoryIndexKey, {"table", db::table::kStorageHistory.name}) << "truncating ...";
    source.bind(*txn, db::table::kStorageHistory);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kAccountHistoryIndexKey, {"table", db::table::kAccountHistory.name}) << "truncating ...";
    source.bind(*txn, db::table::kAccountHistory);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kStorageHistoryIndexKey, 0);
    db::stages::write_stage_progress(txn, db::stages::kAccountHistoryIndexKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kStorageHistoryIndexKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kAccountHistoryIndexKey, 0);
    txn.commit_and_renew();
    SILK_INFO_M(db::stages::kStorageHistoryIndexKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});
    SILK_INFO_M(db::stages::kAccountHistoryIndexKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void HashState stage
    SILK_INFO_M(db::stages::kHashStateKey, {"table", db::table::kHashedCodeHash.name}) << "truncating ...";
    source.bind(*txn, db::table::kHashedCodeHash);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kHashStateKey, {"table", db::table::kHashedStorage.name}) << "truncating ...";
    source.bind(*txn, db::table::kHashedStorage);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kHashStateKey, {"table", db::table::kHashedAccounts.name}) << "truncating ...";
    source.bind(*txn, db::table::kHashedAccounts);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kHashStateKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kHashStateKey, 0);
    txn.commit_and_renew();
    SILK_INFO_M(db::stages::kHashStateKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void Intermediate Hashes stage
    SILK_INFO_M(db::stages::kIntermediateHashesKey, {"table", db::table::kTrieOfStorage.name}) << "truncating ...";
    source.bind(*txn, db::table::kTrieOfStorage);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kIntermediateHashesKey, {"table", db::table::kTrieOfAccounts.name}) << "truncating ...";
    source.bind(*txn, db::table::kTrieOfAccounts);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kIntermediateHashesKey, 0);
    txn.commit_and_renew();
    SILK_INFO_M(db::stages::kIntermediateHashesKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void Execution stage
    SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kBlockReceipts.name}) << "truncating ...";
    source.bind(*txn, db::table::kBlockReceipts);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kLogs.name}) << "truncating ...";
    source.bind(*txn, db::table::kLogs);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kIncarnationMap.name}) << "truncating ...";
    source.bind(*txn, db::table::kIncarnationMap);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kCode.name}) << "truncating ...";
    source.bind(*txn, db::table::kCode);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kPlainCodeHash.name}) << "truncating ...";
    source.bind(*txn, db::table::kPlainCodeHash);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kAccountChangeSet.name}) << "truncating ...";
    source.bind(*txn, db::table::kAccountChangeSet);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kStorageChangeSet.name}) << "truncating ...";
    source.bind(*txn, db::table::kStorageChangeSet);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kCallTraceSet.name}) << "truncating ...";
    source.bind(*txn, db::table::kCallTraceSet);
    txn->clear_map(source.map());
    SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kPlainState.name}) << "truncating ...";
    source.bind(*txn, db::table::kPlainState);
    txn->clear_map(source.map());
    txn.commit_and_renew();

    {
        SILK_INFO_M(db::stages::kExecutionKey, {"table", db::table::kPlainState.name}) << "redo genesis allocations ...";
        // Read chain ID from database
        const auto chain_config{db::read_chain_config(txn)};
        ensure(chain_config.has_value(), "cannot read chain configuration from database");
        // Read genesis data from embedded file
        auto source_data{read_genesis_data(chain_config->chain_id)};
        // Parse genesis JSON data
        // N.B. = instead of {} initialization due to https://github.com/nlohmann/json/issues/2204
        auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
        db::initialize_genesis_allocations(txn, genesis_json);
        txn.commit_and_renew();
    }

    db::stages::write_stage_progress(txn, db::stages::kExecutionKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kExecutionKey, 0);
    txn.commit_and_renew();
    SILK_INFO_M(db::stages::kExecutionKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});

    if (!keep_senders) {
        // Void Senders stage
        SILK_INFO_M(db::stages::kSendersKey, {"table", db::table::kSenders.name}) << "truncating ...";
        source.bind(*txn, db::table::kSenders);
        txn->clear_map(source.map());
        db::stages::write_stage_progress(txn, db::stages::kSendersKey, 0);
        db::stages::write_stage_prune_progress(txn, db::stages::kSendersKey, 0);
        txn.commit_and_renew();
        SILK_INFO_M(db::stages::kSendersKey, {"new height", "0", "in", StopWatch::format(sw.lap().second)});
        if (SignalHandler::signalled()) throw std::runtime_error("Aborted");
    }

    const auto [tp, _] = sw.stop();
    const auto duration = sw.since_start(tp);
    SILK_INFO_M("All done", {"in", StopWatch::format(duration)});
}

void trie_account_analysis(const kvdb::EnvConfig& config) {
    static std::string fmt_hdr{" %-24s %=50s "};

    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{kvdb::open_env(config)};
    auto txn{env.start_read()};

    std::cout << "\n"
              << (boost::format(fmt_hdr) % "Table name" % "%") << "\n"
              << (boost::format(fmt_hdr) % std::string(24, '-') % std::string(50, '-')) << "\n"
              << (boost::format(" %-24s ") % db::table::kTrieOfAccounts.name) << std::flush;

    std::map<size_t, size_t> histogram;
    auto code_cursor = open_cursor(txn, db::table::kTrieOfAccounts);

    Progress progress{50};
    size_t total_entries{txn.get_map_stat(code_cursor.map()).ms_entries};
    progress.set_task_count(total_entries);
    size_t batch_size{progress.get_increment_count()};

    code_cursor.to_first();
    cursor_for_each(code_cursor,
                    [&histogram, &batch_size, &progress](ByteView key, ByteView) {
                        ++histogram[key.size()];
                        if (!--batch_size) {
                            progress.set_current(progress.get_current() + progress.get_increment_count());
                            std::cout << progress.print_interval('.') << std::flush;
                            batch_size = progress.get_increment_count();
                        }
                    });

    progress.set_current(total_entries);
    std::cout << progress.print_interval('.') << "\n";

    if (!histogram.empty()) {
        std::cout << (boost::format(" %-4s %8s") % "Size" % "Count") << "\n"
                  << (boost::format(" %-4s %8s") % std::string(4, '-') % std::string(8, '-')) << "\n";
        for (const auto& [size, usage_count] : histogram) {
            std::cout << (boost::format(" %4u %8u") % size % usage_count) << "\n";
        }
    }
    std::cout << "\n\n";
}

void trie_scan(const kvdb::EnvConfig& config, bool del) {
    auto env{open_env(config)};
    auto txn{env.start_write()};
    std::vector<db::MapConfig> tables{db::table::kTrieOfAccounts, db::table::kTrieOfStorage};
    size_t counter{1};

    for (const auto& map_config : tables) {
        if (SignalHandler::signalled()) {
            break;
        }
        kvdb::PooledCursor cursor(txn, map_config);
        std::cout << " Scanning " << map_config.name << "\n";
        auto data{cursor.to_first(false)};
        while (data) {
            if (data.value.empty()) {
                std::cout << "Empty value at key " << to_hex(kvdb::from_slice(data.key), true) << "\n";
                if (del) {
                    cursor.erase();
                }
            }
            data = cursor.to_next(false);
            if (!--counter) {
                counter = 128;
                if (SignalHandler::signalled()) {
                    break;
                }
            }
        }
    }
    if (!SignalHandler::signalled()) {
        txn.commit();
    }
    std::cout << "\n\n";
}

void trie_integrity(kvdb::EnvConfig& config, bool with_state_coverage, bool continue_scan, bool sanitize) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    using namespace std::chrono_literals;
    std::chrono::time_point start{std::chrono::steady_clock::now()};

    auto env{open_env(config)};
    auto txn{env.start_write()};

    std::string source{db::table::kTrieOfAccounts.name};

    bool is_healthy{true};
    kvdb::PooledCursor trie_cursor1{txn, db::table::kTrieOfAccounts};
    kvdb::PooledCursor trie_cursor2{txn, db::table::kTrieOfAccounts};
    kvdb::PooledCursor state_cursor{txn, db::table::kHashedAccounts};
    size_t prefix_len{0};

    Bytes buffer;
    buffer.reserve(256);

    // First loop Accounts; Second loop Storage
    for (int loop_id{0}; loop_id < 2; ++loop_id) {
        if (loop_id != 0) {
            source = std::string(db::table::kTrieOfStorage.name);
            trie_cursor1.bind(txn, db::table::kTrieOfStorage);
            trie_cursor2.bind(txn, db::table::kTrieOfStorage);
            state_cursor.bind(txn, db::table::kHashedStorage);
            prefix_len = db::kHashedStoragePrefixLength;
        }

        SILK_INFO << "Checking ..." << log::Args{"source", source, "state", (with_state_coverage ? "true" : "false")};

        auto data1{trie_cursor1.to_first(false)};

        while (data1) {
            auto data1_k{kvdb::from_slice(data1.key)};
            auto data1_v{kvdb::from_slice(data1.value)};
            auto node_k{data1_k.substr(prefix_len)};

            // Only unmarshal relevant data without copy on read
            if (data1_v.size() < 6) {
                throw std::runtime_error("At key " + to_hex(data1_k, true) + " invalid value length " +
                                         std::to_string(data1_v.size()) + ". Expected >= 6");
            }
            if ((data1_v.size() - 6) % kHashLength != 0) {
                throw std::runtime_error("At key " + to_hex(data1_k, true) + " invalid hashes count " +
                                         std::to_string(data1_v.size() - 6) + ". Expected multiple of " +
                                         std::to_string(kHashLength));
            }

            const auto node_state_mask{endian::load_big_u16(&data1_v[0])};
            const auto node_tree_mask{endian::load_big_u16(&data1_v[2])};
            const auto node_hash_mask{endian::load_big_u16(&data1_v[4])};
            bool node_has_root{false};

            if (!node_state_mask) {
                // This node should not be here as it does not point to anything
                std::string what{"At key " + to_hex(data1_k, true) +
                                 " node with nil state_mask. Does not point to anything. Shouldn't be here"};
                if (!continue_scan) {
                    throw std::runtime_error(what);
                }
                is_healthy = false;
                std::cout << " " << what << "\n";
            }

            if (!trie::is_subset(node_tree_mask, node_state_mask)) {
                throw std::runtime_error("At key " + to_hex(data1_k, true) + " tree mask " +
                                         std::bitset<16>(node_tree_mask).to_string() + " is not subset of state mask " +
                                         std::bitset<16>(node_state_mask).to_string());
            }
            if (!trie::is_subset(node_hash_mask, node_state_mask)) {
                throw std::runtime_error("At key " + to_hex(data1_k, true) + " hash mask " +
                                         std::bitset<16>(node_hash_mask).to_string() + " is not subset of state mask " +
                                         std::bitset<16>(node_state_mask).to_string());
            }

            data1_v.remove_prefix(6);
            auto expected_hashes_count{static_cast<size_t>(std::popcount(node_hash_mask))};
            auto effective_hashes_count{data1_v.size() / kHashLength};
            if (!(effective_hashes_count == expected_hashes_count ||
                  effective_hashes_count == expected_hashes_count + 1u)) {
                std::string what{"At key " + to_hex(data1_k, true) + " invalid hashes count " +
                                 std::to_string(effective_hashes_count) + ". Expected " +
                                 std::to_string(expected_hashes_count) + " from mask " +
                                 std::bitset<16>(node_hash_mask).to_string()};

                if (!continue_scan) {
                    throw std::runtime_error(what);
                }
                is_healthy = false;
                std::cout << " " << what << "\n";
            } else {
                node_has_root = (effective_hashes_count == expected_hashes_count + 1u);
            }

            /*
             * Nodes with a key length == 0 are root nodes and MUST have a root hash
             */
            if (node_k.empty() && !node_has_root) {
                std::string what{"At key " + to_hex(data1_k, true) + " found root node without root hash"};
                if (!continue_scan) {
                    throw std::runtime_error(what);
                }
                is_healthy = false;
                std::cout << " " << what << "\n";
            } else if (!node_k.empty() && node_has_root) {
                log::Warning("Unexpected root hash", {"key", to_hex(data1_k, true)});
            }

            /*
             * Check children (if any)
             * Each bit set in tree_mask must point to an existing child
             * Example :
             * Current key       : 010203
             * Current tree_mask : 0b0000000000000100
             * Children key      : 01020302 must exist
             *
             * Current key       : 010203
             * Current tree_mask : 0b0000000000100000
             * Children key      : 01020305 must exist
             */

            if (node_tree_mask) {
                buffer.assign(data1_k).push_back('\0');
                for (int i{std::countr_zero(node_tree_mask)}, e{std::bit_width(node_tree_mask)}; i < e; ++i) {
                    if (((1 << i) & node_tree_mask) == 0) {
                        continue;
                    }
                    buffer.back() = static_cast<uint8_t>(i);
                    auto data2{trie_cursor2.lower_bound(kvdb::to_slice(buffer), false)};
                    if (!data2) {
                        throw std::runtime_error("At key " + to_hex(data1_k, true) + " tree mask is " +
                                                 std::bitset<16>(node_tree_mask).to_string() +
                                                 " but there is no child " + std::to_string(i) +
                                                 " in db. LTE found is : null");
                    }
                    auto data2_k{kvdb::from_slice(data2.key)};
                    if (!data2_k.starts_with(buffer)) {
                        throw std::runtime_error("At key " + to_hex(data1_k, true) + " tree mask is " +
                                                 std::bitset<16>(node_tree_mask).to_string() +
                                                 " but there is no child " + std::to_string(i) +
                                                 " in db. LTE found is : " + to_hex(data2_k, true));
                    }
                }
            }

            /*
             * Check parents (if not root)
             * Whether node key length > 1 then at least one parent with a key length shorter than this one must exist
             * Note : length is expressed in nibbles count
             * Example:
             * When node key : 01020304
             * Must find one key in list {010203; 0102} (max jump of 2)
             */

            if (!node_k.empty()) {
                bool found{false};

                for (size_t i{data1_k.size() - 1}; i >= prefix_len && !found; --i) {
                    auto parent_seek_key{data1_k.substr(0, i)};
                    auto data2{trie_cursor2.find(kvdb::to_slice(parent_seek_key), false)};
                    if (!data2) {
                        continue;
                    }
                    found = true;
                    const auto data2_v{kvdb::from_slice(data2.value)};
                    const auto parent_tree_mask{endian::load_big_u16(&data2_v[2])};
                    const auto parent_child_id{static_cast<int>(data1_k[i])};
                    const auto parent_has_tree_bit{(parent_tree_mask & (1 << parent_child_id)) != 0};
                    if (!parent_has_tree_bit) {
                        found = false;
                        if (sanitize) {
                            SILK_WARN << "Erasing orphan" << log::Args{"key", to_hex(data1_k, true)};
                            trie_cursor1.erase();
                            goto next_node;
                        }
                        std::string what{"At key " + to_hex(data1_k, true) + " found parent key " +
                                         to_hex(parent_seek_key, true) +
                                         " with tree mask : " + std::bitset<16>(parent_tree_mask).to_string() +
                                         " and no bit set at position " + std::to_string(parent_child_id)};
                        if (!continue_scan) {
                            throw std::runtime_error(what);
                        }
                        is_healthy = false;
                        std::cout << " " << what << "\n";
                    }
                }

                if (!found) {
                    if (sanitize) {
                        SILK_WARN << "Erasing orphan" << log::Args{"key", to_hex(data1_k, true)};
                        trie_cursor1.erase();
                        goto next_node;
                    }
                    std::string what{"At key " + to_hex(data1_k, true) + " no parent found"};
                    if (!continue_scan) {
                        throw std::runtime_error(what);
                    }
                    is_healthy = false;
                    std::cout << " " << what << "\n";
                }
            }

            /*
             * Slow check for state coverage
             * Whether the node has any hash_state bit set then we must ensure the bits point to
             * an existing hashed state (either account or storage)
             *
             * Example:
             * Current key        : 010203
             * Current state_mask : 0b0000000000000001
             * New Nibbled key    : 01020300
             * Packed key         : 1230
             * A state with prefix in range [1230 ... 1231) must exist
             */

            if (with_state_coverage && node_state_mask) {
                // Buffer is used to build seek key
                buffer.assign(data1_k.substr(prefix_len));
                buffer.push_back('\0');

                auto bits_to_match{buffer.size() * 4};

                // >>> See Erigon /ethdb/kv_util.go::BytesMask
                uint8_t mask{0xff};
                auto fixed_bytes{(bits_to_match + 7) / 8};
                auto shift_bits{bits_to_match & 7};
                if (shift_bits != 0) {
                    mask <<= (8 - shift_bits);
                }
                // <<< See Erigon's ByteMask

                for (int i{std::countr_zero(node_state_mask)}, e{std::bit_width(node_state_mask)}; i < e; ++i) {
                    if (((1 << i) & node_state_mask) == 0) {
                        continue;
                    }

                    bool found{false};
                    buffer.back() = static_cast<uint8_t>(i);

                    Bytes seek{trie::pack_nibbles(buffer)};

                    // On first loop we search HashedAccounts (which is not dup-sorted)
                    if (!loop_id) {
                        auto data3{state_cursor.lower_bound(kvdb::to_slice(seek), false)};
                        if (data3) {
                            auto data3_k{kvdb::from_slice(data3.key)};
                            if (data3_k.size() >= fixed_bytes) {
                                found = (bits_to_match == 0 ||
                                         ((data3_k.substr(0, fixed_bytes - 1) == seek.substr(0, fixed_bytes - 1)) &&
                                          ((data3_k[fixed_bytes - 1] & mask) == (seek[fixed_bytes - 1] & mask))));
                            }
                        }
                        if (!found) {
                            std::string what{"At key " + to_hex(data1_k, true) + " state mask is " +
                                             std::bitset<16>(node_state_mask).to_string() + " but there is no child " +
                                             std::to_string(i) + "," + to_hex(seek, true) + " in hashed state"};
                            if (data3) {
                                auto data3_k{kvdb::from_slice(data3.key)};
                                what.append(" found instead " + to_hex(data3_k, true));
                            }
                            throw std::runtime_error(what);
                        }
                    } else {
                        // On second loop we search HashedStorage (which is dup-sorted)
                        auto data3{state_cursor.lower_bound_multivalue(kvdb::to_slice(data1_k.substr(0, prefix_len)),
                                                                       kvdb::to_slice(seek), false)};
                        if (data3) {
                            auto data3_v{kvdb::from_slice(data3.value)};
                            if (data3_v.size() >= fixed_bytes) {
                                found = (bits_to_match == 0 ||
                                         ((data3_v.substr(0, fixed_bytes - 1) == seek.substr(0, fixed_bytes - 1)) &&
                                          ((data3_v[fixed_bytes - 1] & mask) == (seek[fixed_bytes - 1] & mask))));
                            }
                        }
                        if (!found) {
                            std::string what{"At key " + to_hex(data1_k, true) + " state mask is " +
                                             std::bitset<16>(node_state_mask).to_string() + " but there is no child " +
                                             std::to_string(i) + "," + to_hex(seek, true) + " in state"};
                            if (data3) {
                                auto data3_k{kvdb::from_slice(data3.key)};
                                auto data3_v{kvdb::from_slice(data3.value)};
                                what.append(" found instead " + to_hex(data3_k, true) + to_hex(data3_v, false));
                            }
                            throw std::runtime_error(what);
                        }
                    }
                }
            }

            if (std::chrono::time_point now{std::chrono::steady_clock::now()}; now - start >= 10s) {
                if (SignalHandler::signalled()) {
                    throw std::runtime_error("Interrupted");
                }
                std::swap(start, now);
                log::Info("Checking ...", {"source", source, "key", to_hex(data1_k, true)});
            }

        next_node:
            data1 = trie_cursor1.to_next(false);
        }
    }
    if (!is_healthy) {
        throw std::runtime_error("Check failed");
    }

    SILK_INFO << "Integrity check" << log::Args{"status", "ok"};
    SILK_INFO << "Closing db" << log::Args{"path", env.get_path().string()};
    txn.commit();
    env.close();
}

void trie_reset(const kvdb::EnvConfig& config, bool always_yes) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    if (!always_yes) {
        if (!user_confirmation()) {
            return;
        }
    }

    auto env{open_env(config)};
    kvdb::RWTxnManaged txn{env};
    SILK_INFO << "Clearing ..." << log::Args{"table", db::table::kTrieOfAccounts.name};
    txn->clear_map(db::table::kTrieOfAccounts.name);
    SILK_INFO << "Clearing ..." << log::Args{"table", db::table::kTrieOfStorage.name};
    txn->clear_map(db::table::kTrieOfStorage.name);
    SILK_INFO << "Setting progress ..." << log::Args{"key", db::stages::kIntermediateHashesKey, "value", "0"};
    db::stages::write_stage_progress(txn, db::stages::kIntermediateHashesKey, 0);
    SILK_INFO << "Committing ..." << log::Args{};
    txn.commit_and_renew();
    SILK_INFO << "Closing db" << log::Args{"path", env.get_path().string()};
    env.close();
}

void trie_root(const kvdb::EnvConfig& config) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{open_env(config)};
    kvdb::ROTxnManaged txn{env};
    kvdb::PooledCursor trie_accounts(txn, db::table::kTrieOfAccounts);

    // Retrieve expected state root
    auto hashstate_stage_progress{db::stages::read_stage_progress(txn, db::stages::kHashStateKey)};
    auto intermediate_hashes_stage_progress{db::stages::read_stage_progress(txn, db::stages::kIntermediateHashesKey)};
    if (hashstate_stage_progress != intermediate_hashes_stage_progress) {
        throw std::runtime_error("HashState and Intermediate hashes stage progresses do not match");
    }
    auto header_hash{db::read_canonical_header_hash(txn, hashstate_stage_progress)};
    auto header{db::read_header(txn, hashstate_stage_progress, header_hash->bytes)};
    auto expected_state_root{header->state_root};

    trie::PrefixSet empty_changes{};  // We need this to tell we have no changes. If nullptr means full regen
    trie::HashBuilder hash_builder;

    trie::TrieCursor trie_cursor{trie_accounts, &empty_changes};
    for (auto trie_data{trie_cursor.to_prefix({})}; trie_data.key.has_value(); trie_data = trie_cursor.to_next()) {
        SILKWORM_ASSERT(!trie_data.first_uncovered.has_value());  // Means skip state
        SILK_INFO << "Trie" << log::Args{"key", to_hex(trie_data.key.value(), true), "hash", to_hex(trie_data.hash.value(), true)};
        auto& hash = trie_data.hash.value();
        hash_builder.add_branch_node(trie_data.key.value(), hash, false);
        if (SignalHandler::signalled()) {
            throw std::runtime_error("Interrupted");
        }
        if (trie_data.key->empty()) {
            break;  // just added root node
        }
    }

    const auto computed_state_root = hash_builder.root_hash();
    if (computed_state_root != expected_state_root) {
        log::Error("State root",
                   {"expected", to_hex(expected_state_root, true), "got", to_hex(hash_builder.root_hash(), true)});
    } else {
        log::Info("State root " + to_hex(computed_state_root, true));
    }
}

int main(int argc, char* argv[]) {
    SignalHandler::init();

    CLI::App app("Silkworm staged_pipeline dev tool");
    app.get_formatter()->column_width(50);
    app.require_subcommand(1);  // At least 1 subcommand is required
    log::Settings log_settings{};

    /* Database options (path required) */
    auto db_opts = app.add_option_group("Database", "Database options");
    db_opts->get_formatter()->column_width(35);
    auto shared_opt = db_opts->add_flag("--shared", "Open database in shared mode");
    auto exclusive_opt = db_opts->add_flag("--exclusive", "Open database in exclusive mode")->excludes(shared_opt);

    auto db_opts_paths = db_opts->add_option_group("Path", "Database path")->require_option(1);
    db_opts_paths->get_formatter()->column_width(35);
    auto chaindata_opt = db_opts_paths->add_option("--chaindata", "Path to directory for mdbx.dat");
    auto datadir_opt = db_opts_paths->add_option("--datadir", "Path to data directory")->excludes(chaindata_opt);

    /* Common opts and flags */
    auto app_yes_opt = app.add_flag("-Y,--yes", "Assume yes to all requests of confirmation");
    auto app_dry_opt = app.add_flag("--dry", "Don't commit to db. Only simulate");

    cmd::common::add_logging_options(app, log_settings);

    /* Subcommands */
    // List stages keys and their heights
    auto cmd_stages = app.add_subcommand("stages", "List stages and their actual heights");

    // Stages tool
    auto cmd_stageset = app.add_subcommand("stage_set", "Sets a stage to a new height");
    auto cmd_stageset_name_opt = cmd_stageset->add_option("--name", "Name of the stage to set")->required();
    auto cmd_stageset_height_opt =
        cmd_stageset->add_option("--height", "Block height to set the stage to")->required()->check(CLI::Range(0u, UINT32_MAX));

    // Forward tool
    auto cmd_staged_forward = app.add_subcommand("forward", "Forward staged sync to a given height");
    auto cmd_staged_forward_height =
        cmd_staged_forward->add_option("--height", "Block height to forward the staged sync to")
            ->required()
            ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_staged_forward_start_at_stage_opt =
        cmd_staged_forward->add_option("--start_at_stage", "The name of the pipeline stage to start from");
    auto cmd_staged_forward_stop_before_stage_opt =
        cmd_staged_forward->add_option("--stop_before_stage", "The name of the pipeline stage to stop to");

    // Unwind tool
    auto cmd_staged_unwind = app.add_subcommand("unwind", "Unwind staged sync to a previous height");
    auto cmd_staged_unwind_height =
        cmd_staged_unwind->add_option("--height", "Block height to unwind the staged sync to")
            ->required()
            ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_staged_unwind_remove_blocks =
        cmd_staged_unwind->add_flag("--remove_blocks", "Remove block headers and bodies up to unwind point")
            ->capture_default_str();

    // DebugUnwind tool
    auto cmd_debug_unwind = app.add_subcommand("debug_unwind", "Debug staged sync unwind");
    auto cmd_debug_unwind_height =
        cmd_debug_unwind->add_option("--height", "Block height to debug unwind up to")
            ->required()
            ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_debug_unwind_step =
        cmd_debug_unwind->add_option("--step", "Step")
            ->default_val(1)
            ->check(CLI::Range(1u, UINT32_MAX));
    auto cmd_debug_unwind_start_at_stage_opt =
        cmd_debug_unwind->add_option("--start_at_stage", "The name of the pipeline stage to start from");
    auto cmd_debug_unwind_stop_before_stage_opt =
        cmd_debug_unwind->add_option("--stop_before_stage", "The name of the pipeline stage to stop to");
    auto cmd_debug_unwind_force_opt = cmd_debug_unwind->add_flag("--force", "Force user confirmation");

    // Bisect pipeline
    // Truncates all the work done beyond download stages
    auto cmd_bisect =
        app.add_subcommand("bisect", "Bisect the staged pipeline in the given block interval looking for any failure");
    auto cmd_bisect_from_block_opt =
        cmd_bisect->add_option("--start", "Block number to start bisection from")
            ->required()
            ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_bisect_to_block_opt =
        cmd_bisect->add_option("--end", "Block number to end bisection to")
            ->required()
            ->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_bisect_start_at_stage_opt =
        cmd_bisect->add_option("--start_at_stage", "The name of the pipeline stage to start from");
    auto cmd_bisect_stop_before_stage_opt =
        cmd_bisect->add_option("--stop_before_stage", "The name of the pipeline stage to stop to");

    // Reset after download
    // Truncates all the work done beyond download stages
    auto cmd_reset_to_download =
        app.add_subcommand("reset_to_download", "Reset all work and data written after bodies download");
    auto cmd_reset_to_download_keep_senders_opt =
        cmd_reset_to_download->add_flag("--keep_senders", "Keep the recovered transaction senders");
    auto cmd_reset_to_download_force_opt = cmd_reset_to_download->add_flag("--force", "Force user confirmation");

    // Scan tries
    auto cmd_trie_scan = app.add_subcommand("trie-scan", "Scans tries for empty values");
    auto cmd_trie_scan_delete_opt = cmd_trie_scan->add_flag("--delete", "Delete");

    // Reset tries
    auto cmd_trie_reset = app.add_subcommand("trie-reset", "Resets stage_interhashes");

    // Trie integrity
    auto cmd_trie_integrity = app.add_subcommand("trie-integrity", "Checks trie integrity");
    auto cmd_trie_integrity_state_opt = cmd_trie_integrity->add_flag("--with-state", "Checks covered states (slower)");
    auto cmd_trie_integrity_continue_opt = cmd_trie_integrity->add_flag("--continue", "Keeps scanning on found errors");
    auto cmd_trie_integrity_sanitize_opt = cmd_trie_integrity->add_flag("--sanitize", "Clean orphan nodes");

    // Trie account analysis
    auto cmd_trie_account_analysis =
        app.add_subcommand("trie-account-analysis", "Trie account key sizes analysis");

    // Trie root hash verification
    auto cmd_trie_root = app.add_subcommand("trie-root", "Checks trie root");

    try {
        // Parse arguments and validate
        app.parse(argc, argv);

        auto data_dir_factory = [&chaindata_opt, &datadir_opt]() -> std::unique_ptr<DataDirectory> {
            if (*chaindata_opt) {
                fs::path p{chaindata_opt->as<std::string>()};
                return std::make_unique<DataDirectory>(DataDirectory::from_chaindata(p).path());
            }
            fs::path p{datadir_opt->as<std::string>()};
            return std::make_unique<DataDirectory>(p, /*create=*/false);
        };

        log::init(log_settings);

        auto data_dir = data_dir_factory();
        kvdb::EnvConfig chaindata_env_config{data_dir->chaindata().path().string()};
        chaindata_env_config.shared = shared_opt->as<bool>();
        chaindata_env_config.exclusive = exclusive_opt->as<bool>();

        if (!data_dir->chaindata().exists() || data_dir->chaindata().is_empty()) {
            data_dir->deploy();
            db::chain_data_init(db::ChainDataInitSettings{
                .chaindata_env_config = chaindata_env_config,
                .network_id = 1,
                .init_if_empty = true,
            });
        }
        const auto mdbx_path{kvdb::get_datafile_path(data_dir->chaindata().path())};
        if (!fs::exists(mdbx_path) || !fs::is_regular_file(mdbx_path)) {
            std::cerr << "\n Directory " << data_dir->chaindata().path().string() << " does not contain "
                      << kvdb::kDbDataFileName << "\n";
            return -1;
        }

        // Execute subcommand actions
        if (*cmd_stages) {
            list_stages(chaindata_env_config);
        } else if (*cmd_stageset) {
            set_stage_progress(chaindata_env_config,
                               cmd_stageset_name_opt->as<std::string>(),
                               cmd_stageset_height_opt->as<uint32_t>(),
                               app_dry_opt->as<bool>());
        } else if (*cmd_staged_forward) {
            forward(chaindata_env_config,
                    std::move(data_dir),
                    cmd_staged_forward_height->as<uint32_t>(),
                    app_dry_opt->as<bool>(),
                    cmd_staged_forward_start_at_stage_opt->as<std::string>(),
                    cmd_staged_forward_stop_before_stage_opt->as<std::string>());
        } else if (*cmd_debug_unwind) {
            debug_unwind(chaindata_env_config,
                         std::move(data_dir),
                         cmd_debug_unwind_height->as<uint32_t>(),
                         cmd_debug_unwind_step->as<uint32_t>(),
                         app_dry_opt->as<bool>(),
                         cmd_debug_unwind_force_opt->as<bool>(),
                         cmd_debug_unwind_start_at_stage_opt->as<std::string>(),
                         cmd_debug_unwind_stop_before_stage_opt->as<std::string>());
        } else if (*cmd_staged_unwind) {
            unwind(chaindata_env_config,
                   std::move(data_dir),
                   cmd_staged_unwind_height->as<uint32_t>(),
                   cmd_staged_unwind_remove_blocks->as<bool>(),
                   app_dry_opt->as<bool>());
        } else if (*cmd_bisect) {
            bisect_pipeline(chaindata_env_config,
                            cmd_bisect_from_block_opt->as<BlockNum>(),
                            cmd_bisect_to_block_opt->as<BlockNum>(),
                            app_dry_opt->as<bool>(),
                            cmd_bisect_start_at_stage_opt->as<std::string>(),
                            cmd_bisect_stop_before_stage_opt->as<std::string>());
        } else if (*cmd_reset_to_download) {
            reset_to_download(chaindata_env_config,
                              cmd_reset_to_download_keep_senders_opt->as<bool>(),
                              cmd_reset_to_download_force_opt->as<bool>());
        } else if (*cmd_trie_scan) {
            trie_scan(chaindata_env_config, static_cast<bool>(*cmd_trie_scan_delete_opt));
        } else if (*cmd_trie_reset) {
            trie_reset(chaindata_env_config, static_cast<bool>(*app_yes_opt));
        } else if (*cmd_trie_integrity) {
            trie_integrity(chaindata_env_config,
                           static_cast<bool>(*cmd_trie_integrity_state_opt),
                           static_cast<bool>(*cmd_trie_integrity_continue_opt),
                           static_cast<bool>(*cmd_trie_integrity_sanitize_opt));
        } else if (*cmd_trie_account_analysis) {
            trie_account_analysis(chaindata_env_config);
        } else if (*cmd_trie_root) {
            trie_root(chaindata_env_config);
        }

        return 0;
    } catch (const CLI::ParseError& pe) {
        return app.exit(pe);
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
    } catch (...) {
        std::cerr << "Unexpected undefined error\n";
    }
    return -1;
}
