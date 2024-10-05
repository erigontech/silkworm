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

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <map>
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
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/db/snapshot_bundle_factory_impl.hpp>
#include <silkworm/db/snapshots/snapshot_repository.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>
#include <silkworm/node/stagedsync/stages/stage_interhashes.hpp>

#include "../common/common.hpp"

namespace fs = std::filesystem;
using namespace silkworm;

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
    static auto find_stage(const std::string& stage_name) {
        static const auto kStagesForwardOrder = fix_stages_forward_order();
        auto stage_it = std::find(kStagesForwardOrder.begin(), kStagesForwardOrder.end(), stage_name);
        SILKWORM_ASSERT(stage_it != kStagesForwardOrder.end());
        return stage_it;
    }

    bool operator()(const std::string& lhs, const std::string& rhs) const {
        //std::cout << "lhs=" << lhs << " rhs=" << rhs << "\n";
        return find_stage(lhs) < find_stage(rhs);
    }

  private:
    static stagedsync::ExecutionPipeline::StageNames fix_stages_forward_order() {
        auto stages_forward_order = stagedsync::ExecutionPipeline::stages_forward_order();
        add_after_history_index(stages_forward_order, "StorageHistoryIndex");
        add_after_history_index(stages_forward_order, "AccountHistoryIndex");
        return stages_forward_order;
    }
    static void add_after_history_index(stagedsync::ExecutionPipeline::StageNames& forward_stages, const char* stage) {
        auto history_index_it = std::find(forward_stages.begin(), forward_stages.end(), "HistoryIndex");
        forward_stages.insert(std::next(history_index_it), stage);
    }
};

static std::unique_ptr<snapshots::SnapshotRepository> setup_data_storage(const DataDirectory& data_dir) {
    // Set up the data storage snapshot repository
    snapshots::SnapshotSettings snapshot_settings{
        .repository_dir = data_dir.snapshots().path(),
    };
    auto snapshot_repository = std::make_unique<snapshots::SnapshotRepository>(
        snapshot_settings, std::make_unique<db::SnapshotBundleFactoryImpl>());
    snapshot_repository->reopen_folder();
    db::DataModel::set_snapshot_repository(snapshot_repository.get());
    return snapshot_repository;
}

void list_stages(db::EnvConfig& config) {
    static std::string kTableHeaderFormat{" %-24s %10s "};
    static std::string kTableRowFormat{" %-24s %10u %-8s"};

    auto env = silkworm::db::open_env(config);
    auto txn = env.start_read();
    if (!db::has_map(txn, db::table::kSyncStageProgress.name)) {
        throw std::runtime_error("Either not a Silkworm db or table " +
                                 std::string{db::table::kSyncStageProgress.name} + " not found");
    }

    auto stage_cursor = db::open_cursor(txn, db::table::kSyncStageProgress);
    if (txn.get_map_stat(stage_cursor.map()).ms_entries) {

        std::map<std::string, BlockNum, StageOrderCompare> stage_height_by_name;
        auto result = stage_cursor.to_first(/*throw_notfound =*/false);
        while (result.done) {
            std::string name{result.key.string_view()};
            const size_t height = endian::load_big_u64(static_cast<uint8_t*>(result.value.data()));
            stage_height_by_name.insert_or_assign(std::move(name), height);
            result = stage_cursor.to_next(/*throw_notfound =*/false);
        }

        std::cout << "\n" << (boost::format(kTableHeaderFormat) % "Stage Name" % "Block") << "\n";
        std::cout << (boost::format(kTableHeaderFormat) % std::string(24, '-') % std::string(10, '-')) << "\n";

        for (const auto& [stage_name, stage_height] : stage_height_by_name) {
            // Handle "prune_" stages
            static constexpr std::string_view kPrunePrefix{"prune_"};
            size_t offset{0};
            if (std::memcmp(stage_name.data(), kPrunePrefix.data(), kPrunePrefix.length()) == 0) {
                offset = kPrunePrefix.length();
            }
            const bool known = db::stages::is_known_stage(stage_name.data() + offset);
            std::cout << (boost::format(kTableRowFormat) % stage_name % stage_height %
                          (known ? std::string(8, ' ') : "Unknown")) << "\n";
        }
        std::cout << "\n\n";
    } else {
        std::cout << "\n There are no stages to list\n\n";
    }

    txn.abort();
    env.close(config.shared);
}

void set_stage_progress(db::EnvConfig& config, const std::string& stage_name, uint32_t new_height, bool dry) {
    config.readonly = false;

    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    auto env{silkworm::db::open_env(config)};
    db::RWTxnManaged txn{env};
    if (!db::stages::is_known_stage(stage_name.c_str())) {
        throw std::runtime_error("Stage name " + stage_name + " is not known");
    }
    if (!db::has_map(txn, silkworm::db::table::kSyncStageProgress.name)) {
        throw std::runtime_error("Either non Silkworm db or table " +
                                 std::string(silkworm::db::table::kSyncStageProgress.name) + " not found");
    }
    auto old_height{db::stages::read_stage_progress(txn, stage_name.c_str())};
    db::stages::write_stage_progress(txn, stage_name.c_str(), new_height);
    if (!dry) {
        txn.commit_and_renew();
    }

    std::cout << "\n Stage " << stage_name << " touched from " << old_height << " to " << new_height << "\n\n";
}

void unwind(const DataDirectory& data_dir, db::EnvConfig& config, BlockNum unwind_point, const bool remove_blocks, const bool dry) {
    ensure(config.exclusive, "Function requires exclusive access to database");

    config.readonly = false;

    // Set up the data storage snapshot repository
    const auto snapshot_repository = setup_data_storage(data_dir);

    auto env{silkworm::db::open_env(config)};
    db::RWTxnManaged txn{env};

    // Commit is enabled by default in RWTxn(Managed), so we need to check here
    if (dry) {
        txn.disable_commit();
    } else {
        if (!user_confirmation("Are you sure? This will apply the unwind changes to the database!")) {
            return;
        }
        txn.enable_commit();  // this doesn't harm and works even if default changes
    }

    const auto chain_config{db::read_chain_config(txn)};
    ensure(chain_config.has_value(), "Not an initialized Silkworm db or unknown/custom chain");

    NodeSettings settings{
        .data_directory = std::make_unique<DataDirectory>(),
        .chaindata_env_config = config,
        .chain_config = chain_config};

    stagedsync::ExecutionPipeline stage_pipeline{&settings};
    const auto unwind_result{stage_pipeline.unwind(txn, unwind_point)};

    ensure(unwind_result == stagedsync::Stage::Result::kSuccess,
           [&]() { return "unwind failed: " + std::string{magic_enum::enum_name<stagedsync::Stage::Result>(unwind_result)}; });

    std::cout << "\n Staged pipeline unwind up to block: " << unwind_point << " completed\n";

    // In consensus-separated Sync/Execution design block headers and bodies are stored by the Sync component
    // not by the Execution component: hence, ExecutionPipeline will not remove them during unwind phase
    if (remove_blocks) {
        std::cout << " Removing also block headers and bodies up to block: " << unwind_point << "\n";

        // Remove the block bodies up to the unwind point
        const auto body_cursor{txn.rw_cursor(db::table::kBlockBodies)};
        const auto start_key{db::block_key(unwind_point)};
        std::size_t erased_bodies{0};
        auto body_data{body_cursor->lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};
        while (body_data) {
            body_cursor->erase();
            ++erased_bodies;
            body_data = body_cursor->to_next(/*throw_notfound=*/false);
        }
        std::cout << " Removed block bodies erased: " << erased_bodies << "\n";

        // Remove the block headers up to the unwind point
        const auto header_cursor{txn.rw_cursor(db::table::kHeaders)};
        std::size_t erased_headers{0};
        auto header_data{header_cursor->lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};
        while (header_data) {
            header_cursor->erase();
            ++erased_headers;
            header_data = header_cursor->to_next(/*throw_notfound=*/false);
        }
        std::cout << " Removed block headers erased: " << erased_headers << "\n";

        // Remove the canonical hashes up to the unwind point
        const auto canonical_cursor{txn.rw_cursor(db::table::kCanonicalHashes)};
        std::size_t erased_hashes{0};
        auto hash_data{canonical_cursor->lower_bound(db::to_slice(start_key), /*throw_notfound=*/false)};
        while (hash_data) {
            canonical_cursor->erase();
            ++erased_hashes;
            hash_data = canonical_cursor->to_next(/*throw_notfound=*/false);
        }
        std::cout << " Removed canonical hashes erased: " << erased_hashes << "\n";

        txn.commit_and_stop();
    }
}

void forward(const DataDirectory& data_dir, db::EnvConfig& config, BlockNum forward_point, const bool dry,
             const std::string& start_at_stage, const std::string& stop_before_stage) {
    ensure(config.exclusive, "Function requires exclusive access to database");

    config.readonly = false;

    // Set up the data storage snapshot repository
    const auto snapshot_repository = setup_data_storage(data_dir);

    Environment::set_start_at_stage(start_at_stage);
    Environment::set_stop_before_stage(stop_before_stage);

    auto env = silkworm::db::open_env(config);
    db::RWTxnManaged txn{env};

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

    NodeSettings settings{
        .data_directory = std::make_unique<DataDirectory>(datadir_path),
        .chaindata_env_config = config,
        .chain_config = chain_config};

    // Start timer scheduler thread to observe stage progress during processing
    std::thread ioc_thread{[&]() {
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{settings.asio_context.get_executor()};
        settings.asio_context.run();
    }};
    auto _ = gsl::finally([&]() {
        settings.asio_context.stop();
        ioc_thread.join();
    });

    stagedsync::ExecutionPipeline stage_pipeline{&settings};

    const auto forward_result = stage_pipeline.forward(txn, forward_point);
    ensure(forward_result == stagedsync::Stage::Result::kSuccess,
           [&]() { return "forward failed: " + std::string{magic_enum::enum_name<stagedsync::Stage::Result>(forward_result)}; });

    std::cout << "\n Staged pipeline forward up to block: " << forward_point << " completed\n";
}

void bisect_pipeline(const DataDirectory& data_dir, db::EnvConfig& config, BlockNum start, BlockNum end, const bool dry,
                     const std::string& start_at_stage, const std::string& stop_before_stage) {
    ensure(config.exclusive, "Function requires exclusive access to database");
    ensure(end >= start, "Function requires valid block interval: end must be greater than or equal to start");

    config.readonly = false;

    // Set up the data storage snapshot repository
    const auto snapshot_repository = setup_data_storage(data_dir);

    Environment::set_start_at_stage(start_at_stage);
    Environment::set_stop_before_stage(stop_before_stage);

    auto env = silkworm::db::open_env(config);
    db::RWTxnManaged txn{env};

    // Commit is enabled by default in RWTxn(Managed), so we need to check here
    if (dry) {
        txn.disable_commit();
    } else {
        if (!user_confirmation("Are you sure? This will apply the changes to the database!")) {
            return;
        }
        txn.enable_commit();  // this doesn't harm and works even if default changes
    }

    // We should have all the blocks in the interval already validated by stages Headers+Bodies
    /*const auto headers_progress = db::stages::read_stage_progress(txn, db::stages::kHeadersKey);
    ensure(headers_progress >= end, [&]() { return "Insufficient Headers progress: " + std::to_string(headers_progress); });
    const auto bodies_progress = db::stages::read_stage_progress(txn, db::stages::kBlockBodiesKey);
    ensure(bodies_progress >= end, [&]() { return "Insufficient Bodies progress: " + std::to_string(bodies_progress); });*/

    // TODO(canepat) batch or one block at a time for each pipeline forward

    const auto chain_config{db::read_chain_config(txn)};
    ensure(chain_config.has_value(), "Uninitialized Silkworm db or unknown/custom chain");

    const auto datadir_path = std::filesystem::path{config.path}.parent_path();
    SILK_INFO << "Bisect: datadir=" << datadir_path.string();

    NodeSettings settings{
        .data_directory = std::make_unique<DataDirectory>(datadir_path),
        .chaindata_env_config = config,
        .chain_config = chain_config};
    std::thread ioc_thread{[&]() {
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{settings.asio_context.get_executor()};
        settings.asio_context.run();
    }};

    auto _ = gsl::finally([&]() { settings.asio_context.stop(); });

    stagedsync::ExecutionPipeline stage_pipeline{&settings};

    // Unwind staged pipeline down to the previous block wrt start
    const auto unwind_point = start - 1;
    SILK_INFO << "Bisect: unwind down to block=" << unwind_point << " START";
    const auto first_unwind_result = stage_pipeline.unwind(txn, unwind_point);
    ensure(first_unwind_result == stagedsync::Stage::Result::kSuccess,
           [&]() { return "unwind failed: " + std::string{magic_enum::enum_name<stagedsync::Stage::Result>(first_unwind_result)}; });
    SILK_INFO << "Bisect: unwind down to block=" << unwind_point << " END";

    uint64_t left_point = start, right_point = end;
    while (left_point < right_point) {
        uint64_t median_point = (left_point + right_point) >> 1;
        SILK_INFO << "Bisect: forward from=" << left_point << " to=" << right_point << " START";
        const auto forward_result = stage_pipeline.forward(txn, right_point);
        SILK_INFO << "Bisect: forward from=" << left_point << " to=" << right_point << " END";
        if (forward_result == stagedsync::Stage::Result::kSuccess) {
            left_point = right_point;
            if (right_point < end) {
                right_point = (median_point + end) >> 1;
            }
        } else {
            right_point = median_point;
            SILK_INFO << "Bisect: unwind down to block=" << start << " START";
            const auto unwind_result = stage_pipeline.unwind(txn, start);
            ensure(unwind_result == stagedsync::Stage::Result::kSuccess,
                   [&]() { return "unwind failed: " + std::string{magic_enum::enum_name<stagedsync::Stage::Result>(unwind_result)}; });
            SILK_INFO << "Bisect: unwind down to block=" << start << " END";
        }
    }

    if (left_point == end && right_point == end) {
        SILK_INFO << "Bisect: success at block=" << right_point;
    } else {
        SILK_INFO << "Bisect: failed at block=" << right_point;
    }
}

void do_reset_to_download(db::EnvConfig& config, bool keep_senders) {
    if (!config.exclusive) {
        throw std::runtime_error("Function requires exclusive access to database");
    }

    if (!user_confirmation("Are you sure? This will erase the database content written after BlockHashes stage!")) {
        return;
    }

    log::Info() << "OK, please be patient...";

    auto env{silkworm::db::open_env(config)};
    db::RWTxnManaged txn(env);

    StopWatch sw(/*auto_start=*/true);
    // Void finish stage
    db::stages::write_stage_progress(txn, db::stages::kFinishKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kFinishKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void TxLookup stage
    SILK_INFO << db::stages::kTxLookupKey << log::Args{"table", db::table::kTxLookup.name} << "truncating ...";
    db::PooledCursor source(*txn, db::table::kTxLookup);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kTxLookupKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kTxLookupKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kTxLookupKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void LogIndex stage
    SILK_INFO << db::stages::kLogIndexKey << log::Args{"table", db::table::kLogTopicIndex.name} << " truncating ...";
    source.bind(*txn, db::table::kLogTopicIndex);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kLogIndexKey << log::Args{"table", db::table::kLogAddressIndex.name} << " truncating ...";
    source.bind(*txn, db::table::kLogAddressIndex);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kLogIndexKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kLogIndexKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kLogIndexKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void HistoryIndex (StorageHistoryIndex + AccountHistoryIndex) stage
    SILK_INFO << db::stages::kStorageHistoryIndexKey << log::Args{"table", db::table::kStorageHistory.name} << " truncating ...";
    source.bind(*txn, db::table::kStorageHistory);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kAccountHistoryIndexKey << log::Args{"table", db::table::kAccountHistory.name} << " truncating ...";
    source.bind(*txn, db::table::kAccountHistory);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kStorageHistoryIndexKey, 0);
    db::stages::write_stage_progress(txn, db::stages::kAccountHistoryIndexKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kStorageHistoryIndexKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kAccountHistoryIndexKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kStorageHistoryIndexKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    SILK_INFO << db::stages::kAccountHistoryIndexKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void HashState stage
    SILK_INFO << db::stages::kHashStateKey << log::Args{"table", db::table::kHashedCodeHash.name} << " truncating ...";
    source.bind(*txn, db::table::kHashedCodeHash);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kHashStateKey << log::Args{"table", db::table::kHashedStorage.name} << " truncating ...";
    source.bind(*txn, db::table::kHashedStorage);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kHashStateKey << log::Args{"table", db::table::kHashedAccounts.name} << " truncating ...";
    source.bind(*txn, db::table::kHashedAccounts);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kHashStateKey, 0);
    db::stages::write_stage_prune_progress(txn, db::stages::kHashStateKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kHashStateKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void Intermediate Hashes stage
    SILK_INFO << db::stages::kIntermediateHashesKey << log::Args{"table", db::table::kTrieOfStorage.name} << " truncating ...";
    source.bind(*txn, db::table::kTrieOfStorage);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kIntermediateHashesKey << log::Args{"table", db::table::kTrieOfAccounts.name} << " truncating ...";
    source.bind(*txn, db::table::kTrieOfAccounts);
    txn->clear_map(source.map());
    db::stages::write_stage_progress(txn, db::stages::kIntermediateHashesKey, 0);
    txn.commit_and_renew();
    SILK_INFO << db::stages::kIntermediateHashesKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
    if (SignalHandler::signalled()) throw std::runtime_error("Aborted");

    // Void Execution stage
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kBlockReceipts.name} << " truncating ...";
    source.bind(*txn, db::table::kBlockReceipts);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kLogs.name} << " truncating ...";
    source.bind(*txn, db::table::kLogs);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kIncarnationMap.name} << " truncating ...";
    source.bind(*txn, db::table::kIncarnationMap);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kCode.name} << " truncating ...";
    source.bind(*txn, db::table::kCode);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kPlainCodeHash.name} << " truncating ...";
    source.bind(*txn, db::table::kPlainCodeHash);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kAccountChangeSet.name} << " truncating ...";
    source.bind(*txn, db::table::kAccountChangeSet);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kStorageChangeSet.name} << " truncating ...";
    source.bind(*txn, db::table::kStorageChangeSet);
    txn->clear_map(source.map());
    SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kPlainState.name} << " truncating ...";
    source.bind(*txn, db::table::kPlainState);
    txn->clear_map(source.map());
    txn.commit_and_renew();

    {
        SILK_INFO << db::stages::kExecutionKey << log::Args{"table", db::table::kPlainState.name} << " redo genesis allocations ...";
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
    SILK_INFO << db::stages::kExecutionKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};

    if (!keep_senders) {
        // Void Senders stage
        SILK_INFO << db::stages::kSendersKey << log::Args{"table", db::table::kSenders.name} << " truncating ...";
        source.bind(*txn, db::table::kSenders);
        txn->clear_map(source.map());
        db::stages::write_stage_progress(txn, db::stages::kSendersKey, 0);
        db::stages::write_stage_prune_progress(txn, db::stages::kSendersKey, 0);
        txn.commit_and_renew();
        SILK_INFO << db::stages::kSendersKey << log::Args{"new height", "0", "in", StopWatch::format(sw.lap().second)};
        if (SignalHandler::signalled()) throw std::runtime_error("Aborted");
    }

    auto [tp, _]{sw.stop()};
    auto duration{sw.since_start(tp)};
    SILK_INFO << "All done" << log::Args{"in", StopWatch::format(duration)};
}

int main(int argc, char* argv[]) {
    SignalHandler::init();

    CLI::App app("Silkworm execute_pipeline dev tool");
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
    auto app_dry_opt = app.add_flag("--dry", "Don't commit to db. Only simulate");

    cmd::common::add_logging_options(app, log_settings);

    /* Subcommands */
    // List stages keys and their heights
    auto cmd_stages = app.add_subcommand("stages", "List stages and their actual heights");

    // Stages tool
    auto cmd_stageset = app.add_subcommand("stage-set", "Sets a stage to a new height");
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

    // Bisect pipeline
    // Truncates all the work done beyond download stages
    auto cmd_bisect =
        app.add_subcommand("bisect", "Bisect the staged pipeline in the given block interval looking for any failure");
    auto cmd_bisect_from_block_opt =
        cmd_bisect->add_option("--start", "Block number to start bisection from")
            ->required()->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_bisect_to_block_opt =
        cmd_bisect->add_option("--end", "Block number to end bisection to")
            ->required()->check(CLI::Range(0u, UINT32_MAX));
    auto cmd_bisect_start_at_stage_opt =
        cmd_bisect->add_option("--start_at_stage", "The name of the pipeline stage to start from");
    auto cmd_bisect_stop_before_stage_opt =
        cmd_bisect->add_option("--stop_before_stage", "The name of the pipeline stage to stop to");

    // Reset after download
    // Truncates all the work done beyond download stages
    auto cmd_reset_to_download =
        app.add_subcommand("reset-to-download", "Reset all work and data written after bodies download");
    auto cmd_reset_to_download_keep_senders_opt =
        cmd_reset_to_download->add_flag("--keep-senders", "Keep the recovered transaction senders");

    try {
        // Parse arguments and validate
        app.parse(argc, argv);

        auto data_dir_factory = [&chaindata_opt, &datadir_opt]() -> DataDirectory {
            if (*chaindata_opt) {
                fs::path p{chaindata_opt->as<std::string>()};
                return DataDirectory::from_chaindata(p);
            }
            fs::path p{datadir_opt->as<std::string>()};
            return DataDirectory(p, /*create=*/false);
        };

        log::init(log_settings);

        // Set origin data directory
        DataDirectory data_dir{data_dir_factory()};
        if (!data_dir.chaindata().exists() || data_dir.chaindata().is_empty()) {
            std::cerr << "\n Directory " << data_dir.chaindata().path().string() << " does not exist or is empty\n";
            return -1;
        }
        auto mdbx_path{db::get_datafile_path(data_dir.chaindata().path())};
        if (!fs::exists(mdbx_path) || !fs::is_regular_file(mdbx_path)) {
            std::cerr << "\n Directory " << data_dir.chaindata().path().string() << " does not contain "
                      << db::kDbDataFileName << "\n";
            return -1;
        }

        db::EnvConfig chaindata_env_config{data_dir.chaindata().path().string()};
        chaindata_env_config.shared = shared_opt->as<bool>();
        chaindata_env_config.exclusive = exclusive_opt->as<bool>();

        // Execute subcommand actions
        if (*cmd_stages) {
            list_stages(chaindata_env_config);
        } else if (*cmd_stageset) {
            set_stage_progress(chaindata_env_config,
                               cmd_stageset_name_opt->as<std::string>(),
                               cmd_stageset_height_opt->as<uint32_t>(),
                               app_dry_opt->as<bool>());
        } else if (*cmd_staged_forward) {
            forward(data_dir,
                    chaindata_env_config,
                    cmd_staged_forward_height->as<uint32_t>(),
                    app_dry_opt->as<bool>(),
                    cmd_staged_forward_start_at_stage_opt->as<std::string>(),
                    cmd_staged_forward_stop_before_stage_opt->as<std::string>());
        } else if (*cmd_staged_unwind) {
            unwind(data_dir,
                   chaindata_env_config,
                   cmd_staged_unwind_height->as<uint32_t>(),
                   cmd_staged_unwind_remove_blocks->as<bool>(),
                   app_dry_opt->as<bool>());
        } else if (*cmd_bisect) {
            bisect_pipeline(data_dir,
                            chaindata_env_config,
                            cmd_bisect_from_block_opt->as<BlockNum>(),
                            cmd_bisect_to_block_opt->as<BlockNum>(),
                            app_dry_opt->as<bool>(),
                            cmd_bisect_start_at_stage_opt->as<std::string>(),
                            cmd_bisect_stop_before_stage_opt->as<std::string>());
        } else if (*cmd_reset_to_download) {
            do_reset_to_download(chaindata_env_config,
                                 cmd_reset_to_download_keep_senders_opt->as<bool>());
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
