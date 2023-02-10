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

#include <magic_enum.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/snapshot/config.hpp>
#include <silkworm/snapshot/path.hpp>
#include <silkworm/types/hash.hpp>

namespace silkworm {

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
        log::Info() << "snapshot sync disabled, no snapshot must be downloaded";
        return true;
    }

    if (settings_.no_downloader) {
        repository_.reopen_folder();
        if (settings_.verify_on_startup) {
            repository_.verify();
        }
        return true;
    }

    const auto snapshot_file_names = db::read_snapshots(txn);

    const bool download_completed = download_snapshots(snapshot_file_names);
    if (!download_completed) return false;

    db::write_snapshots(*txn, snapshot_file_names);

    return index_snapshots(txn, snapshot_file_names);
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
    for (const auto& preverified_snapshot : snapshot_config->preverified_snapshots()) {
        SILK_INFO << "[Snapshots] adding info hash for: " << preverified_snapshot.file_name;
        client_.add_info_hash(preverified_snapshot.file_name, preverified_snapshot.torrent_hash);
    }

    client_thread_ = std::thread([&]() { client_.execute_loop(); });

    // TODO(canepat) wait for download completion signalled by client on condition variable
    // TODO(canepat) currently just wait for loop end: seeding MUST be disabled otherwise we wait forever
    SILKWORM_ASSERT(!settings_.bittorrent_settings.seeding);
    if (client_thread_.joinable()) client_thread_.join();

    return true;
}

bool SnapshotSync::index_snapshots(db::RWTxn& txn, const std::vector<std::string>& snapshot_file_names) {
    if (!settings_.enabled) {
        log::Info() << "snapshot sync disabled, no index must be created";
        return true;
    }

    if (repository_.idx_max_block() < repository_.segment_max_block()) {
        repository_.build_missing_indexes();
        repository_.reopen_folder();
    }

    const auto max_block_available = repository_.max_block_available();
    const auto snapshot_config = snapshot::Config::lookup_known_config(config_.chain_id, snapshot_file_names);
    const auto configured_max_block_number = snapshot_config->max_block_number();
    if (max_block_available < configured_max_block_number) {
        // Iterate on block header snapshots and write header-related tables
        etl::Collector hash2bn_collector{};
        intx::uint256 total_difficulty{0};
        repository_.for_each_header([&](const BlockHeader* header) -> bool {
            SILK_DEBUG << "Header number: " << header->number << " hash: " << to_hex(header->hash());
            const auto block_number = header->number;
            const auto block_hash = header->hash();

            // Write block header into kDifficulty table
            total_difficulty += header->difficulty;
            db::write_total_difficulty(*txn, block_number, block_hash, total_difficulty);

            // Write block header into kCanonicalHashes table
            db::write_canonical_hash(*txn, block_number, block_hash);

            // Collect entries for later loading kHeaderNumbers table
            Bytes encoded_block_number{sizeof(uint64_t), '\0'};
            endian::store_big_u64(encoded_block_number.data(), block_number);
            hash2bn_collector.collect({block_hash.bytes, encoded_block_number});
            return true;
        });
        db::Cursor header_numbers_cursor{*txn, db::table::kHeaderNumbers};
        hash2bn_collector.load(header_numbers_cursor);

        // Reset sequence for kBlockTransactions table
        const auto view_result = repository_.view_tx_segment(max_block_available, [&](const auto* tx_sn) {
            // TODO(canepat) implement recsplit.Index
            const auto last_tx_id = /*tx_sn->idx_txn_hash()->base_data_id() +*/ tx_sn->item_count();
            db::reset_map_sequence(*txn, db::table::kBlockTransactions.name, last_tx_id + 1);
            return true;
        });
        if (view_result != SnapshotRepository::ViewResult::kWalkSuccess) {
            log::Error() << "snapshot not found for block: " << max_block_available;
            return false;
        }

        // Update head block header in kHeadHeader table
        // TODO(canepat) Get canonical hash from block reader
        const Hash canonical_hash{};
        db::write_head_header_hash(*txn, canonical_hash);

        // Update progress for related stages
        db::stages::write_stage_progress(*txn, db::stages::kBlockBodiesKey, max_block_available);
        db::stages::write_stage_progress(*txn, db::stages::kBlockHashesKey, max_block_available);
        db::stages::write_stage_progress(*txn, db::stages::kSendersKey, max_block_available);
    }

    // TODO(canepat) add_headers_from_snapshots towards header downloader persisted link queue

    return true;
}

void SnapshotSync::stop() {
    client_.stop();
    if (client_thread_.joinable()) {
        client_thread_.join();
    }
}

}  // namespace silkworm
