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

#include "snapshot_sync.hpp"

#include <atomic>
#include <exception>
#include <latch>
#include <stdexcept>

#include <boost/asio/this_coro.hpp>
#include <gsl/util>
#include <magic_enum.hpp>

#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/blocks/headers/header_snapshot.hpp>
#include <silkworm/db/mdbx/etl_mdbx_collector.hpp>
#include <silkworm/db/snapshot_bundle_factory_impl.hpp>
#include <silkworm/db/snapshots/config.hpp>
#include <silkworm/db/snapshots/index_builder.hpp>
#include <silkworm/db/snapshots/snapshot_path.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>

namespace silkworm::db {

using namespace silkworm::snapshots;

//! \warning Hash provider for std::filesystem::path necessary to avoid the following error in Clang + LLVM 16
//! \verbatim
//! error: call to implicitly-deleted default constructor of 'std::hash<std::filesystem::path>'
//! \endverbatim
struct PathHasher {
    auto operator()(const std::filesystem::path& p) const noexcept {
        return std::filesystem::hash_value(p);
    }
};

SnapshotSync::SnapshotSync(
    boost::asio::any_io_executor executor,
    snapshots::SnapshotSettings settings,
    ChainId chain_id,
    mdbx::env& chaindata_env,
    std::filesystem::path tmp_dir_path,
    stagedsync::StageScheduler& stage_scheduler)
    : settings_{std::move(settings)},
      chain_id_{chain_id},
      chaindata_env_{chaindata_env},
      repository_{settings_, std::make_unique<db::SnapshotBundleFactoryImpl>()},
      client_{settings_.bittorrent_settings},
      snapshot_freezer_{db::ROAccess{chaindata_env_}, repository_, stage_scheduler, tmp_dir_path, settings.keep_blocks},
      snapshot_merger_{repository_, tmp_dir_path},
      is_stopping_latch_{1},
      setup_done_promise_{executor} {
}

Task<void> SnapshotSync::run() {
    using namespace concurrency::awaitable_wait_for_all;

    [[maybe_unused]] auto _ = gsl::finally([this]() { this->is_stopping_latch_.count_down(); });

    if (!settings_.enabled) {
        log::Info() << "Snapshot sync disabled, no snapshot must be downloaded";
        co_return;
    }

    co_await (setup_and_run() && client_.async_run("bit-torrent"));
}

Task<void> SnapshotSync::setup_and_run() {
    using namespace concurrency::awaitable_wait_for_all;

    co_await setup();

    co_await (
        snapshot_freezer_.run_loop() &&
        snapshot_merger_.run_loop());
}

// Raise file descriptor limit per process
void raise_fd_limit() {
    constexpr uint64_t kMaxFileDescriptors{10'240};
    const bool set_fd_result = os::set_max_file_descriptors(kMaxFileDescriptors);
    if (!set_fd_result) {
        throw std::runtime_error{"Cannot increase max file descriptor up to " + std::to_string(kMaxFileDescriptors)};
    }
}

Task<void> SnapshotSync::setup() {
    raise_fd_limit();

    // Snapshot sync - download chain from peers using snapshot files
    co_await download_and_index_snapshots();

    // Update chain and stage progresses in database according to available snapshots
    db::RWTxnManaged rw_txn{chaindata_env_};
    update_database(rw_txn, repository_.max_block_available(), [this] { return is_stopping_latch_.try_wait(); });
    rw_txn.commit_and_stop();

    // Set snapshot repository into snapshot-aware database access
    db::DataModel::set_snapshot_repository(&repository_);

    setup_done_promise_.set_value(true);
}

Task<void> SnapshotSync::wait_for_setup() {
    auto future = setup_done_promise_.get_future();
    co_await future.get_async();
}

Task<void> SnapshotSync::download_and_index_snapshots() {
    if (!settings_.enabled) {
        SILK_INFO << "SnapshotSync: snapshot sync disabled, no snapshot must be downloaded";
        co_return;
    }
    SILK_INFO << "SnapshotSync: snapshot repository: " << settings_.repository_dir.string();

    if (!settings_.no_downloader) {
        co_await download_snapshots();
    }

    repository_.remove_stale_indexes();
    co_await build_missing_indexes();

    repository_.reopen_folder();

    const auto max_block_available = repository_.max_block_available();
    SILK_INFO << "SnapshotSync: max block available: " << max_block_available;

    const auto snapshot_config = Config::lookup_known_config(chain_id_);
    const auto configured_max_block_number = snapshot_config.max_block_number();
    SILK_INFO << "SnapshotSync: configured max block: " << configured_max_block_number;
}

Task<void> SnapshotSync::download_snapshots() {
    const auto missing_block_ranges = repository_.missing_block_ranges();
    if (!missing_block_ranges.empty()) {
        SILK_INFO << "SnapshotSync: downloading missing snapshots";
    }

    const auto snapshot_config = Config::lookup_known_config(chain_id_);
    if (snapshot_config.preverified_snapshots().empty()) {
        SILK_ERROR << "SnapshotSync: no preverified snapshots found";
        throw std::runtime_error("SnapshotSync: no preverified snapshots found");
    }
    const size_t num_snapshots = snapshot_config.preverified_snapshots().size();
    SILK_INFO << "SnapshotSync: sync started: [0/" << num_snapshots << "]";

    auto log_added = [](const std::filesystem::path& snapshot_file) {
        SILK_TRACE << "SnapshotSync: download started for: " << snapshot_file.filename().string();
    };
    const auto added_connection = client_.added_subscription.connect(log_added);

    size_t completed = 0;
    auto log_stats = [&](lt::span<const int64_t> counters) {
        // Log progress just once in a while because our BitTorrent notifications rely on alert polling so quite chatty
        static int notification_count{0};
        if (notification_count++ != 30) return;
        notification_count = 0;

        SILK_INFO << "SnapshotSync: sync in progress: [" << completed << "/" << num_snapshots << "]";
        if (log::test_verbosity(log::Level::kTrace)) {
            std::string counters_dump;
            for (int i{0}; i < counters.size(); ++i) {
                const auto& stats_metric = client_.stats_metrics().at(static_cast<std::size_t>(i));
                counters_dump.append(stats_metric.name);
                counters_dump.append("=");
                counters_dump.append(std::to_string(counters[i]));
                if (i != counters.size() - 1) counters_dump.append(", ");
            }
            SILK_TRACE << "SnapshotSync: counters dump [" << counters_dump << "]";
        }
    };
    const auto stats_connection = client_.stats_subscription.connect(log_stats);

    auto executor = co_await boost::asio::this_coro::executor;
    // make the buffer bigger so that try_send always succeeds in case of duplicate files (see snapshot_set below)
    concurrency::Channel<std::filesystem::path> completed_channel{executor, num_snapshots * 2};
    auto log_completed = [&](const std::filesystem::path& snapshot_file) {
        completed_channel.try_send(snapshot_file);
    };
    const auto completed_connection = client_.completed_subscription.connect(log_completed);

    for (const auto& preverified_snapshot : snapshot_config.preverified_snapshots()) {
        SILK_TRACE << "SnapshotSync: adding info hash for preverified: " << preverified_snapshot.file_name;
        client_.add_info_hash(preverified_snapshot.file_name, preverified_snapshot.torrent_hash);
    }

    // The same snapshot segment may be downloaded multiple times in case of content change over time and
    // hence notified for completion multiple times. We need to count each snapshot segment just once here
    std::unordered_set<std::filesystem::path, PathHasher> snapshot_set;

    // Wait for download completion of all snapshots
    for (completed = 0; completed < num_snapshots; completed++) {
        std::filesystem::path snapshot_file;
        do {
            snapshot_file = co_await completed_channel.receive();
        } while (snapshot_set.contains(snapshot_file));
        const auto [_, inserted] = snapshot_set.insert(snapshot_file);
        SILKWORM_ASSERT(inserted);
        SILK_INFO << "SnapshotSync: download completed for: " << snapshot_file.filename().string()
                  << " [" << (completed + 1) << "/" << num_snapshots << "]";
    }

    SILK_INFO << "SnapshotSync: sync completed: [" << num_snapshots << "/" << num_snapshots << "]";

    added_connection.disconnect();
    completed_connection.disconnect();
    stats_connection.disconnect();
}

Task<void> SnapshotSync::build_missing_indexes() {
    ThreadPool workers;
    // on errors do not wait for any remaining indexing tasks that were not started (because of not enough threads)
    [[maybe_unused]] auto _ = gsl::finally([&workers]() { workers.pause(); });

    // Determine the missing indexes and build them in parallel
    const auto missing_indexes = repository_.missing_indexes();
    if (missing_indexes.empty()) {
        co_return;
    }

    SILK_INFO << "SnapshotSync: " << missing_indexes.size() << " missing indexes to build";
    const size_t total_tasks = missing_indexes.size();
    std::atomic_size_t done_tasks;
    auto executor = co_await boost::asio::this_coro::executor;
    concurrency::Channel<size_t> done_channel{executor, total_tasks};

    for (const auto& index : missing_indexes) {
        workers.push_task([&]() {
            try {
                SILK_INFO << "SnapshotSync: building index " << index->path().filename() << " ...";
                index->build();
                done_tasks++;
                SILK_INFO << "SnapshotSync: built index " << index->path().filename() << ";"
                          << " progress: " << (done_tasks * 100 / total_tasks) << "% "
                          << done_tasks << " of " << total_tasks << " indexes ready";
                done_channel.try_send(done_tasks);
            } catch (const std::exception& ex) {
                SILK_CRIT << "SnapshotSync: build index: " << index->path().filename() << " failed [" << ex.what() << "]";
                throw;
            }
        });
    }

    // Wait for all missing indexes to be built
    while (done_tasks < total_tasks) {
        co_await done_channel.receive();
    }

    SILK_INFO << "SnapshotSync: built missing indexes";
}

void SnapshotSync::update_database(db::RWTxn& txn, BlockNum max_block_available, std::function<bool()> is_stopping) {
    update_block_headers(txn, max_block_available, is_stopping);
    update_block_bodies(txn, max_block_available);
    update_block_hashes(txn, max_block_available);
    update_block_senders(txn, max_block_available);
}

void SnapshotSync::update_block_headers(db::RWTxn& txn, BlockNum max_block_available, std::function<bool()> is_stopping) {
    // Check if Headers stage progress has already reached the max block in snapshots
    const auto last_progress{db::stages::read_stage_progress(txn, db::stages::kHeadersKey)};
    if (last_progress >= max_block_available) {
        return;
    }

    SILK_INFO << "SnapshotSync: database update started";

    // Iterate on block header snapshots and write header-related tables
    db::etl_mdbx::Collector hash2bn_collector{};
    intx::uint256 total_difficulty{0};
    uint64_t block_count{0};

    for (const auto& bundle_ptr : repository_.view_bundles()) {
        const auto& bundle = *bundle_ptr;
        for (const BlockHeader& header : HeaderSnapshotReader{bundle.header_snapshot}) {
            SILK_TRACE << "SnapshotSync: header number=" << header.number << " hash=" << Hash{header.hash()}.to_hex();
            const auto block_number = header.number;
            if (block_number > max_block_available) continue;

            const auto block_hash = header.hash();

            // Write block header into kDifficulty table
            total_difficulty += header.difficulty;
            db::write_total_difficulty(txn, block_number, block_hash, total_difficulty);

            // Write block header into kCanonicalHashes table
            db::write_canonical_hash(txn, block_number, block_hash);

            // Collect entries for later loading kHeaderNumbers table
            Bytes block_hash_bytes{block_hash.bytes, kHashLength};
            Bytes encoded_block_number(sizeof(BlockNum), '\0');
            endian::store_big_u64(encoded_block_number.data(), block_number);
            hash2bn_collector.collect({std::move(block_hash_bytes), std::move(encoded_block_number)});

            if (++block_count % 1'000'000 == 0) {
                SILK_INFO << "SnapshotSync: processing block header=" << block_number << " count=" << block_count;
                if (is_stopping()) return;
            }
        }
    }

    db::PooledCursor header_numbers_cursor{txn, db::table::kHeaderNumbers};
    hash2bn_collector.load(header_numbers_cursor);
    SILK_INFO << "SnapshotSync: database table HeaderNumbers updated";

    // Update head block header in kHeadHeader table
    const auto canonical_hash{db::read_canonical_header_hash(txn, max_block_available)};
    ensure(canonical_hash.has_value(), "SnapshotSync: no canonical head hash found");
    db::write_head_header_hash(txn, *canonical_hash);
    SILK_INFO << "SnapshotSync: database table HeadHeader updated";

    // Update Headers stage progress to the max block in snapshots (w/ STOP_AT_BLOCK support)
    const auto stop_at_block = Environment::get_stop_at_block();
    const BlockNum stage_progress{stop_at_block ? *stop_at_block : max_block_available};
    db::stages::write_stage_progress(txn, db::stages::kHeadersKey, stage_progress);

    SILK_INFO << "SnapshotSync: database Headers stage progress updated [" << stage_progress << "]";
}

void SnapshotSync::update_block_bodies(db::RWTxn& txn, BlockNum max_block_available) {
    // Check if BlockBodies stage progress has already reached the max block in snapshots
    const auto last_progress{db::stages::read_stage_progress(txn, db::stages::kBlockBodiesKey)};
    if (last_progress >= max_block_available) {
        return;
    }

    // Reset sequence for kBlockTransactions table
    const auto [tx_snapshot, _] = repository_.find_segment(SnapshotType::transactions, max_block_available);
    ensure(tx_snapshot.has_value(), "SnapshotSync: snapshots max block not found in any snapshot");
    const auto last_tx_id = tx_snapshot->index.base_data_id() + tx_snapshot->snapshot.item_count();
    db::reset_map_sequence(txn, db::table::kBlockTransactions.name, last_tx_id + 1);
    SILK_INFO << "SnapshotSync: database table BlockTransactions sequence reset";

    // Update BlockBodies stage progress to the max block in snapshots (w/ STOP_AT_BLOCK support)
    const auto stop_at_block = Environment::get_stop_at_block();
    const BlockNum stage_progress{stop_at_block ? *stop_at_block : max_block_available};
    db::stages::write_stage_progress(txn, db::stages::kBlockBodiesKey, stage_progress);

    SILK_INFO << "SnapshotSync: database BlockBodies stage progress updated [" << stage_progress << "]";
}

void SnapshotSync::update_block_hashes(db::RWTxn& txn, BlockNum max_block_available) {
    // Check if BlockHashes stage progress has already reached the max block in snapshots
    const auto last_progress{db::stages::read_stage_progress(txn, db::stages::kBlockHashesKey)};
    if (last_progress >= max_block_available) {
        return;
    }

    // Update BlockHashes stage progress to the max block in snapshots (w/ STOP_AT_BLOCK support)
    const auto stop_at_block = Environment::get_stop_at_block();
    const BlockNum stage_progress{stop_at_block ? *stop_at_block : max_block_available};
    db::stages::write_stage_progress(txn, db::stages::kBlockHashesKey, stage_progress);

    SILK_INFO << "SnapshotSync: database BlockHashes stage progress updated [" << stage_progress << "]";
}

void SnapshotSync::update_block_senders(db::RWTxn& txn, BlockNum max_block_available) {
    // Check if Senders stage progress has already reached the max block in snapshots
    const auto last_progress{db::stages::read_stage_progress(txn, db::stages::kSendersKey)};
    if (last_progress >= max_block_available) {
        return;
    }

    // Update Senders stage progress to the max block in snapshots (w/ STOP_AT_BLOCK support)
    const auto stop_at_block = Environment::get_stop_at_block();
    const BlockNum stage_progress{stop_at_block ? *stop_at_block : max_block_available};
    db::stages::write_stage_progress(txn, db::stages::kSendersKey, stage_progress);

    SILK_INFO << "SnapshotSync: database Senders stage progress updated [" << stage_progress << "]";
}

}  // namespace silkworm::db
