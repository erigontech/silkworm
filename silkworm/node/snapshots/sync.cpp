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

#include "sync.hpp"

#include <exception>
#include <latch>

#include <magic_enum.hpp>

#include <silkworm/core/types/hash.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>
#include <silkworm/node/db/etl_mdbx_collector.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/snapshots/config.hpp>
#include <silkworm/node/snapshots/index.hpp>
#include <silkworm/node/snapshots/path.hpp>

namespace silkworm::snapshots {

//! Interval between successive checks for either completion or stop requested
static constexpr std::chrono::seconds kCheckCompletionInterval{1};

SnapshotSync::SnapshotSync(SnapshotRepository* repository, const ChainConfig& config)
    : repository_{repository},
      settings_{repository_->settings()},
      config_(config),
      client_{settings_.bittorrent_settings} {
    ensure(repository_, "SnapshotSync: SnapshotRepository is null");
}

SnapshotSync::~SnapshotSync() {
    SnapshotSync::stop();
}

bool SnapshotSync::download_and_index_snapshots(db::RWTxn& txn) {
    if (!settings_.enabled) {
        SILK_INFO << "SnapshotSync: snapshot sync disabled, no snapshot must be downloaded";
        return true;
    }

    SILK_INFO << "SnapshotSync: snapshot repository: " << settings_.repository_dir.string();

    if (settings_.no_downloader) {
        reopen();
        return true;
    }

    const auto snapshot_file_names = db::read_snapshots(txn);

    const bool download_completed = download_snapshots(snapshot_file_names);
    if (!download_completed) return false;

    db::write_snapshots(txn, snapshot_file_names);

    SILK_INFO << "SnapshotSync: file names saved into db count=" << std::to_string(snapshot_file_names.size());

    index_snapshots();

    const auto max_block_available = repository_->max_block_available();
    SILK_INFO << "SnapshotSync: max block available: " << max_block_available
              << " (segment max block: " << repository_->segment_max_block()
              << ", idx max block: " << repository_->idx_max_block() << ")";

    const auto snapshot_config = Config::lookup_known_config(config_.chain_id, snapshot_file_names);
    const auto configured_max_block_number = snapshot_config.max_block_number();
    SILK_INFO << "SnapshotSync: configured max block: " << configured_max_block_number;

    // Update chain and stage progresses in database according to available snapshots
    update_database(txn, max_block_available);

    return true;
}

void SnapshotSync::reopen() {
    repository_->reopen_folder();
    SILK_INFO << "SnapshotSync: reopen completed segment_max_block=" << std::to_string(repository_->segment_max_block())
              << " idx_max_block=" << std::to_string(repository_->idx_max_block());
}

bool SnapshotSync::download_snapshots(const std::vector<std::string>& snapshot_file_names) {
    const auto missing_block_ranges = repository_->missing_block_ranges();
    if (not missing_block_ranges.empty()) {
        SILK_WARN << "SnapshotSync: downloading missing snapshots";
    }

    for (auto [block_from, block_to] : missing_block_ranges) {
        for (const auto type : magic_enum::enum_values<SnapshotType>()) {
            auto snapshot_path = SnapshotPath::from(repository_->path(), kSnapshotV1, block_from, block_to, type);
            if (!snapshot_path.torrent_file_needed()) {
                continue;
            }
            SILK_INFO << "SnapshotSync: seeding a new snapshot [DOING NOTHING NOW]";
            // TODO(canepat) create torrent file
            // client.add_torrent(snapshot_path.create_torrent_file());
        }
    }

    const auto snapshot_config = Config::lookup_known_config(config_.chain_id, snapshot_file_names);
    if (snapshot_config.preverified_snapshots().empty()) {
        SILK_ERROR << "SnapshotSync: no preverified snapshots found";
        return false;
    }
    for (const auto& preverified_snapshot : snapshot_config.preverified_snapshots()) {
        SILK_TRACE << "SnapshotSync: adding info hash for preverified: " << preverified_snapshot.file_name;
        client_.add_info_hash(preverified_snapshot.file_name, preverified_snapshot.torrent_hash);
    }

    auto log_added = [](const std::filesystem::path& snapshot_file) {
        SILK_TRACE << "SnapshotSync: download started for: " << snapshot_file.filename().string();
    };
    const auto added_connection = client_.added_subscription.connect(log_added);

    const auto num_snapshots{std::ptrdiff_t(snapshot_config.preverified_snapshots().size())};
    SILK_INFO << "SnapshotSync: sync started: [0/" << num_snapshots << "]";

    static int completed{0};
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

    std::latch download_done{num_snapshots};
    auto log_completed = [&](const std::filesystem::path& snapshot_file) {
        SILK_INFO << "SnapshotSync: download completed for: " << snapshot_file.filename().string()
                  << " [" << ++completed << "/" << num_snapshots << "]";
        download_done.count_down();
    };
    const auto completed_connection = client_.completed_subscription.connect(log_completed);

    client_thread_ = std::thread([&]() {
        log::set_thread_name("bit-torrent");
        try {
            client_.execute_loop();
        } catch (const std::exception& ex) {
            SILK_CRIT << "SnapshotSync: BitTorrentClient execute_loop exception: " << ex.what();
            std::terminate();
        }
    });

    // Wait for download completion of all snapshots or stop request
    while (not download_done.try_wait() and not is_stopping()) {
        std::this_thread::sleep_for(kCheckCompletionInterval);
    }

    SILK_INFO << "SnapshotSync: sync completed: [" << num_snapshots << "/" << num_snapshots << "]";

    added_connection.disconnect();
    completed_connection.disconnect();
    stats_connection.disconnect();

    reopen();
    return true;
}

void SnapshotSync::index_snapshots() {
    if (!settings_.enabled) {
        SILK_INFO << "SnapshotSync: snapshot sync disabled, no index must be created";
        return;
    }

    // Build any missing snapshot index if needed, then reopen
    if (repository_->idx_max_block() < repository_->segment_max_block()) {
        SILK_INFO << "SnapshotSync: missing indexes detected, rebuild started";
        build_missing_indexes();
        reopen();
    }
}

bool SnapshotSync::stop() {
    const bool result = Stoppable::stop();
    client_.stop();
    if (client_thread_.joinable()) {
        client_thread_.join();
    }
    return result;
}

void SnapshotSync::build_missing_indexes() {
    ThreadPool workers;

    // Determine the missing indexes and build them in parallel
    const auto missing_indexes = repository_->missing_indexes();
    for (const auto& index : missing_indexes) {
        workers.push_task([=]() {
            try {
                SILK_INFO << "SnapshotSync: build index: " << index->path().filename() << " start";
                index->build();
                SILK_INFO << "SnapshotSync: build index: " << index->path().filename() << " end";
            } catch (const std::exception& ex) {
                SILK_CRIT << "SnapshotSync: build index: " << index->path().filename() << " failed [" << ex.what() << "]";
                throw;
            }
        });
    }

    // Wait for all missing indexes to be built or stop request
    while (workers.get_tasks_total() and not is_stopping()) {
        std::this_thread::sleep_for(kCheckCompletionInterval);
    }
    // Wait for any already-started-but-unfinished work in case of stop request
    workers.pause();
    workers.wait_for_tasks();
}

void SnapshotSync::update_database(db::RWTxn& txn, BlockNum max_block_available) {
    update_block_headers(txn, max_block_available);
    update_block_bodies(txn, max_block_available);
    update_block_hashes(txn, max_block_available);
    update_block_senders(txn, max_block_available);
}

void SnapshotSync::update_block_headers(db::RWTxn& txn, BlockNum max_block_available) {
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
    repository_->for_each_header([&](const BlockHeader* header) -> bool {
        SILK_TRACE << "SnapshotSync: header number=" << header->number << " hash=" << Hash{header->hash()}.to_hex();
        const auto block_number = header->number;
        if (block_number > max_block_available) return true;

        const auto block_hash = header->hash();

        // Write block header into kDifficulty table
        total_difficulty += header->difficulty;
        db::write_total_difficulty(txn, block_number, block_hash, total_difficulty);

        // Write block header into kCanonicalHashes table
        db::write_canonical_hash(txn, block_number, block_hash);

        // Collect entries for later loading kHeaderNumbers table
        Bytes block_hash_bytes{block_hash.bytes, kHashLength};
        Bytes encoded_block_number{sizeof(uint64_t), '\0'};
        endian::store_big_u64(encoded_block_number.data(), block_number);
        hash2bn_collector.collect({std::move(block_hash_bytes), std::move(encoded_block_number)});

        if (++block_count % 1'000'000 == 0) {
            SILK_INFO << "SnapshotSync: processing block header=" << block_number << " count=" << block_count;
            if (is_stopping()) return false;
        }

        return true;
    });
    db::PooledCursor header_numbers_cursor{txn, db::table::kHeaderNumbers};
    hash2bn_collector.load(header_numbers_cursor);
    SILK_INFO << "SnapshotSync: database table HeaderNumbers updated";

    // Update head block header in kHeadHeader table
    const auto canonical_hash{db::read_canonical_hash(txn, max_block_available)};
    ensure(canonical_hash.has_value(), "SnapshotSync::save no canonical head hash found");
    db::write_head_header_hash(txn, *canonical_hash);
    SILK_INFO << "SnapshotSync: database table HeadHeader updated";

    // Update Headers stage progress to the max block in snapshots
    db::stages::write_stage_progress(txn, db::stages::kHeadersKey, max_block_available);

    SILK_INFO << "SnapshotSync: database Headers stage progress updated";
}

void SnapshotSync::update_block_bodies(db::RWTxn& txn, BlockNum max_block_available) {
    // Check if BlockBodies stage progress has already reached the max block in snapshots
    const auto last_progress{db::stages::read_stage_progress(txn, db::stages::kBlockBodiesKey)};
    if (last_progress >= max_block_available) {
        return;
    }

    // Reset sequence for kBlockTransactions table
    const auto tx_snapshot = repository_->find_tx_segment(max_block_available);
    ensure(tx_snapshot, "SnapshotSync: snapshots max block not found in any snapshot");
    const auto last_tx_id = tx_snapshot->idx_txn_hash()->base_data_id() + tx_snapshot->item_count();
    db::reset_map_sequence(txn, db::table::kBlockTransactions.name, last_tx_id + 1);
    SILK_INFO << "SnapshotSync: database table BlockTransactions sequence reset";

    // Update BlockBodies stage progress to the max block in snapshots
    db::stages::write_stage_progress(txn, db::stages::kBlockBodiesKey, max_block_available);

    SILK_INFO << "SnapshotSync: database BlockBodies stage progress updated";
}

void SnapshotSync::update_block_hashes(db::RWTxn& txn, BlockNum max_block_available) {
    // Check if BlockHashes stage progress has already reached the max block in snapshots
    const auto last_progress{db::stages::read_stage_progress(txn, db::stages::kBlockHashesKey)};
    if (last_progress >= max_block_available) {
        return;
    }

    // Update BlockHashes stage progress to the max block in snapshots
    db::stages::write_stage_progress(txn, db::stages::kBlockHashesKey, max_block_available);

    SILK_INFO << "SnapshotSync: database BlockHashes stage progress updated";
}

void SnapshotSync::update_block_senders(db::RWTxn& txn, BlockNum max_block_available) {
    // Check if Senders stage progress has already reached the max block in snapshots
    const auto last_progress{db::stages::read_stage_progress(txn, db::stages::kSendersKey)};
    if (last_progress >= max_block_available) {
        return;
    }

    // Update Senders stage progress to the max block in snapshots
    db::stages::write_stage_progress(txn, db::stages::kSendersKey, max_block_available);

    SILK_INFO << "SnapshotSync: database Senders stage progress updated";
}

}  // namespace silkworm::snapshots
