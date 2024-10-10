/*
   Copyright 2024 The Silkworm Authors

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

#include "freezer.hpp"

#include <filesystem>
#include <stdexcept>
#include <vector>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/common/filesystem.hpp>
#include <silkworm/infra/common/log.hpp>

#include "access_layer.hpp"
#include "blocks/bodies/body_snapshot_freezer.hpp"
#include "blocks/headers/header_snapshot_freezer.hpp"
#include "datastore/snapshots/snapshot_bundle.hpp"
#include "datastore/snapshots/snapshot_path.hpp"
#include "datastore/snapshots/snapshot_writer.hpp"
#include "prune_mode.hpp"
#include "snapshot_freezer.hpp"
#include "transactions/txn_snapshot_freezer.hpp"

namespace silkworm::db {

using namespace silkworm::snapshots;

struct FreezerResult : public DataMigrationResult {
    SnapshotBundle bundle;

    explicit FreezerResult(SnapshotBundle bundle1)
        : bundle(std::move(bundle1)) {}
    ~FreezerResult() override = default;
};

static BlockNum get_tip_num(ROTxn& txn) {
    auto [num, _] = db::read_canonical_head(txn);
    return num;
}

static BlockNum get_first_stored_header_num(ROTxn& txn) {
    auto num_opt = db::read_stored_header_number_after(txn, 1);
    return num_opt.value_or(0);
}

static std::optional<uint64_t> get_next_base_txn_id(BlockNum number) {
    auto body = DataModel::read_body_for_storage_from_snapshot(number);
    if (!body) return std::nullopt;
    return body->base_txn_id + body->txn_count;
}

std::unique_ptr<DataMigrationCommand> Freezer::next_command() {
    BlockNum last_frozen = snapshots_.max_block_available();
    BlockNum start = (last_frozen > 0) ? last_frozen + 1 : 0;
    BlockNum end = start + kChunkSize;

    BlockNum tip = [this] {
        auto db_tx = db_access_.start_ro_tx();
        return get_tip_num(db_tx);
    }();

    uint64_t base_txn_id = [last_frozen]() -> uint64_t {
        if (last_frozen == 0) return 0;
        auto id = get_next_base_txn_id(last_frozen);
        SILKWORM_ASSERT(id.has_value());
        return *id;
    }();

    if (end + kFullImmutabilityThreshold <= tip) {
        return std::make_unique<FreezerCommand>(FreezerCommand{{start, end}, base_txn_id});
    }
    return {};
}

static const SnapshotFreezer& get_snapshot_freezer(SnapshotType type) {
    static HeaderSnapshotFreezer header_snapshot_freezer;
    static BodySnapshotFreezer body_snapshot_freezer;
    static TransactionSnapshotFreezer txn_snapshot_freezer;

    switch (type) {
        case SnapshotType::headers:
            return header_snapshot_freezer;
        case SnapshotType::bodies:
            return body_snapshot_freezer;
        case SnapshotType::transactions:
            return txn_snapshot_freezer;
        default:
            SILKWORM_ASSERT(false);
            throw std::runtime_error("invalid type");
    }
}

std::shared_ptr<DataMigrationResult> Freezer::migrate(std::unique_ptr<DataMigrationCommand> command) {
    auto& freezer_command = dynamic_cast<FreezerCommand&>(*command);
    auto range = freezer_command.range;

    auto bundle = snapshots_.bundle_factory().make(tmp_dir_path_, range);
    for (auto& snapshot_ref : bundle.snapshots()) {
        auto path = snapshot_ref.get().path();
        SnapshotFileWriter file_writer{path, tmp_dir_path_};
        {
            auto db_tx = db_access_.start_ro_tx();
            auto& freezer = get_snapshot_freezer(path.type());
            freezer.copy(db_tx, freezer_command, file_writer);
        }
        SnapshotFileWriter::flush(std::move(file_writer));
    }

    return std::make_shared<FreezerResult>(std::move(bundle));
}

void Freezer::index(std::shared_ptr<DataMigrationResult> result) {
    auto& freezer_result = dynamic_cast<FreezerResult&>(*result);
    auto& bundle = freezer_result.bundle;
    snapshots_.build_indexes(bundle);
}

void Freezer::commit(std::shared_ptr<DataMigrationResult> result) {
    auto& freezer_result = dynamic_cast<FreezerResult&>(*result);
    auto& bundle = freezer_result.bundle;
    move_files(bundle.files(), snapshots_.path());

    auto final_bundle = snapshots_.bundle_factory().make(snapshots_.path(), bundle.block_range());
    snapshots_.add_snapshot_bundle(std::move(final_bundle));
}

BlockNumRange Freezer::cleanup_range() {
    BlockNum last_frozen = snapshots_.max_block_available();

    BlockNum first_stored_header_num = [this] {
        auto db_tx = db_access_.start_ro_tx();
        return get_first_stored_header_num(db_tx);
    }();

    BlockNum end = (last_frozen > 0) ? last_frozen + 1 : 0;
    BlockNum start = (first_stored_header_num > 0) ? first_stored_header_num : end;
    return BlockNumRange{start, end};
}

Task<void> Freezer::cleanup() {
    BlockNumRange range = cleanup_range();
    if (range.start >= range.end) co_return;
    log::Debug(name()) << "cleanup " << range.to_string();

    if (keep_blocks_) {
        log::Debug(name()) << "skipping cleanup";
        co_return;
    }

    co_await stage_scheduler_.schedule([this, range](RWTxn& db_tx) {
        this->cleanup(db_tx, range);
    });
}

void Freezer::cleanup(RWTxn& db_tx, BlockNumRange range) const {
    get_snapshot_freezer(SnapshotType::transactions).cleanup(db_tx, range);
    get_snapshot_freezer(SnapshotType::bodies).cleanup(db_tx, range);
    get_snapshot_freezer(SnapshotType::headers).cleanup(db_tx, range);
}

}  // namespace silkworm::db
