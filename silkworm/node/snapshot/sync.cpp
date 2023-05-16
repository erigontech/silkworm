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

#include <chrono>
#include <latch>

#include <magic_enum.hpp>

#include <silkworm/core/types/hash.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/etl/collector.hpp>
#include <silkworm/node/snapshot/config.hpp>
#include <silkworm/node/snapshot/path.hpp>

namespace silkworm::snapshot {

//! Interval between successive checks for either completion or stop requested
static constexpr std::chrono::seconds kCheckCompletionInterval{1};

SnapshotSync::SnapshotSync(const SnapshotSettings& settings, const ChainConfig& config)
    : settings_(settings),
      config_(config),
      repository_{settings},
      client_{settings_.bittorrent_settings} {}

SnapshotSync::~SnapshotSync() {
    stop();
}

bool SnapshotSync::download_and_index_snapshots(db::RWTxn& txn) {
    if (!settings_.enabled) {
        log::Info() << "[Snapshots] snapshot sync disabled, no snapshot must be downloaded";
        return true;
    }

    log::Info() << "[Snapshots] snapshot repository: " << settings_.repository_dir.string();

    if (settings_.no_downloader) {
        reopen();
        return true;
    }

    const auto snapshot_file_names = db::read_snapshots(txn);

    const bool download_completed = download_snapshots(snapshot_file_names);
    if (!download_completed) return false;

    reopen();

    db::write_snapshots(txn, snapshot_file_names);

    log::Info() << "[Snapshots] file names saved into db" << log::Args{"count", std::to_string(snapshot_file_names.size())};

    return index_snapshots(txn, snapshot_file_names);
}

void SnapshotSync::reopen() {
    repository_.reopen_folder();
    log::Info() << "[Snapshots] open_and_verify completed"
                << log::Args{"segment_max_block", std::to_string(repository_.segment_max_block()),
                             "idx_max_block", std::to_string(repository_.idx_max_block())};
}

bool SnapshotSync::download_snapshots(const std::vector<std::string>& snapshot_file_names) {
    const auto missing_block_ranges = repository_.missing_block_ranges();
    if (not missing_block_ranges.empty()) {
        SILK_WARN << "[Snapshots] downloading missing snapshots";
    }

    for (auto [block_from, block_to] : missing_block_ranges) {
        for (const auto type : magic_enum::enum_values<SnapshotType>()) {
            auto snapshot_path = SnapshotPath::from(repository_.path(), kSnapshotV1, block_from, block_to, type);
            if (!snapshot_path.torrent_file_needed()) {
                continue;
            }
            SILK_INFO << "[Snapshots] seeding a new snapshot [DOING NOTHING NOW]";
            // TODO(canepat) create torrent file
            // client.add_torrent(snapshot_path.create_torrent_file());
        }
    }

    const auto snapshot_config = snapshot::Config::lookup_known_config(config_.chain_id, snapshot_file_names);
    if (snapshot_config->preverified_snapshots().empty()) {
        log::Error() << "[Snapshots] no preverified snapshots found";
        return false;
    }
    for (const auto& preverified_snapshot : snapshot_config->preverified_snapshots()) {
        SILK_INFO << "[Snapshots] adding info hash for preverified: " << preverified_snapshot.file_name;
        client_.add_info_hash(preverified_snapshot.file_name, preverified_snapshot.torrent_hash);
    }

    auto log_added = [](const std::filesystem::path& snapshot_file) {
        SILK_INFO << "[Snapshots] download started for: " << snapshot_file.filename().string();
    };
    client_.added_subscription.connect(log_added);

    auto log_stats = [&](lt::span<const int64_t> counters) {
        std::string counters_dump;
        for (int i{0}; i < counters.size(); ++i) {
            const auto& stats_metric = client_.stats_metrics().at(static_cast<std::size_t>(i));
            counters_dump.append(stats_metric.name);
            counters_dump.append("=");
            counters_dump.append(std::to_string(counters[i]));
            if (i != counters.size() - 1) counters_dump.append(", ");
        }
        SILK_DEBUG << "[Snapshots] download progress: [" << counters_dump << "]";
    };
    client_.stats_subscription.connect(log_stats);

    const auto num_snapshots{std::ptrdiff_t(snapshot_config->preverified_snapshots().size())};
    SILK_INFO << "[Snapshots] sync started: [0/" << num_snapshots << "]";

    std::latch download_done{num_snapshots};
    auto log_completed = [&](const std::filesystem::path& snapshot_file) {
        static int completed{0};
        SILK_INFO << "[Snapshots] download completed for: " << snapshot_file.filename().string() << " [" << ++completed
                  << "/" << num_snapshots << "]";
        download_done.count_down();
    };
    client_.completed_subscription.connect(log_completed);

    client_thread_ = std::thread([&]() {
        log::set_thread_name("bit-torrent");
        client_.execute_loop();
    });

    // Wait for download completion of all snapshots or stop request
    while (not download_done.try_wait() and not is_stopping()) {
        std::this_thread::sleep_for(kCheckCompletionInterval);
    }

    SILK_INFO << "[Snapshots] sync completed: [" << num_snapshots << "/" << num_snapshots << "]";

    return true;
}

bool SnapshotSync::index_snapshots(db::RWTxn& txn, const std::vector<std::string>& snapshot_file_names) {
    if (!settings_.enabled) {
        log::Info() << "[Snapshots] snapshot sync disabled, no index must be created";
        return true;
    }

    // Build any missing snapshot index if needed, then reopen
    if (repository_.idx_max_block() < repository_.segment_max_block()) {
        log::Info() << "[Snapshots] missing indexes detected, rebuild started";
        build_missing_indexes();
        repository_.reopen_folder();
    }

    const auto max_block_available = repository_.max_block_available();
    log::Info() << "[Snapshots] max block available: " << max_block_available
                << " (segment max block: " << repository_.segment_max_block()
                << ", idx max block: " << repository_.idx_max_block() << ")";

    const auto snapshot_config = snapshot::Config::lookup_known_config(config_.chain_id, snapshot_file_names);
    const auto configured_max_block_number = snapshot_config->max_block_number();
    log::Info() << "[Snapshots] configured max block: " << configured_max_block_number;
    if (max_block_available < configured_max_block_number) {
        // Iterate on block header snapshots and write header-related tables
        return save(txn, max_block_available);
    }

    // TODO(canepat) add_headers_from_snapshots towards header downloader persisted link queue

    return true;
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
    thread_pool workers;

    // Determine the missing indexes and build them in parallel
    const auto missing_indexes = repository_.missing_indexes();
    for (const auto& index : missing_indexes) {
        workers.submit([=]() {
            log::Info() << "[Snapshots] Build index: " << index->path().filename() << " start";
            index->build();
            log::Info() << "[Snapshots] Build index: " << index->path().filename() << " end";
        });
    }

    // Wait for all missing indexes to be built or stop request
    while (workers.get_tasks_total() and not is_stopping()) {
        std::this_thread::sleep_for(kCheckCompletionInterval);
    }
    // Wait for any already-started-but-unfinished work in case of stop request
    workers.paused = true;
    workers.wait_for_tasks();
}

bool SnapshotSync::save(db::RWTxn& txn, BlockNum max_block_available) {
    // Iterate on block header snapshots and write header-related tables
    etl::Collector hash2bn_collector{};
    intx::uint256 total_difficulty{0};
    uint64_t block_count{0};
    repository_.for_each_header([&](const BlockHeader* header) -> bool {
        SILK_DEBUG << "Header number: " << header->number << " hash: " << to_hex(header->hash());
        const auto block_number = header->number;
        const auto block_hash = header->hash();

        // Write block header into kDifficulty table
        total_difficulty += header->difficulty;
        db::write_total_difficulty(txn, block_number, block_hash, total_difficulty);

        // Write block header into kCanonicalHashes table
        db::write_canonical_hash(txn, block_number, block_hash);

        // Collect entries for later loading kHeaderNumbers table
        Bytes encoded_block_number{sizeof(uint64_t), '\0'};
        endian::store_big_u64(encoded_block_number.data(), block_number);
        hash2bn_collector.collect({block_hash.bytes, encoded_block_number});

        if (++block_count % 1'000'000 == 0) {
            log::Info() << "[Snapshots] processing block header: " << block_number << " count=" << block_count;
            if (is_stopping()) return false;
        }

        return true;
    });
    db::PooledCursor header_numbers_cursor{txn, db::table::kHeaderNumbers};
    hash2bn_collector.load(header_numbers_cursor);

    // Reset sequence for kBlockTransactions table
    const auto view_result = repository_.view_tx_segment(max_block_available, [&](const auto* tx_sn) {
        const auto last_tx_id = tx_sn->idx_txn_hash()->base_data_id() + tx_sn->item_count();
        db::reset_map_sequence(txn, db::table::kBlockTransactions.name, last_tx_id + 1);
        return true;
    });
    if (view_result != SnapshotRepository::ViewResult::kWalkSuccess) {
        log::Error() << "[Snapshots] snapshot not found for block: " << max_block_available;
        return false;
    }

    // Update head block header in kHeadHeader table
    // TODO(canepat) Get canonical hash from block reader
    const Hash canonical_hash{};
    db::write_head_header_hash(txn, canonical_hash);

    // Update progress for related stages
    db::stages::write_stage_progress(txn, db::stages::kHeadersKey, max_block_available);
    db::stages::write_stage_progress(txn, db::stages::kBlockBodiesKey, max_block_available);
    db::stages::write_stage_progress(txn, db::stages::kBlockHashesKey, max_block_available);
    db::stages::write_stage_progress(txn, db::stages::kSendersKey, max_block_available);

    return true;
}

}  // namespace silkworm::snapshot
