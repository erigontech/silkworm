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

#include <cassert>
#include <filesystem>
#include <stdexcept>
#include <vector>

#include <silkworm/core/common/base.hpp>

#include "access_layer.hpp"
#include "bodies/body_snapshot_freezer.hpp"
#include "headers/header_snapshot_freezer.hpp"
#include "prune_mode.hpp"
#include "snapshot_freezer.hpp"
#include "snapshots/path.hpp"
#include "snapshots/snapshot_bundle.hpp"
#include "snapshots/snapshot_writer.hpp"
#include "transactions/txn_snapshot_freezer.hpp"

namespace silkworm::db {

using namespace silkworm::snapshots;

struct FreezerCommand : public DataMigrationCommand {
    BlockNumRange range;

    explicit FreezerCommand(BlockNumRange range1)
        : range(std::move(range1)) {}
    ~FreezerCommand() override = default;
};

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

std::unique_ptr<DataMigrationCommand> Freezer::next_command() {
    BlockNum last_frozen = snapshots_.max_block_available();
    BlockNum start = (last_frozen > 0) ? last_frozen + 1 : 0;
    BlockNum end = start + kChunkSize;

    BlockNum tip = [this] {
        auto db_tx = db_access_.start_ro_tx();
        return get_tip_num(db_tx);
    }();

    if (end + kFullImmutabilityThreshold <= tip) {
        return std::make_unique<FreezerCommand>(FreezerCommand{{start, end}});
    }
    return {};
}

static const SnapshotFreezer& get_snapshot_freezer(SnapshotType type) {
    static HeaderSnapshotFreezer header_snapshot_freezer;
    static BodySnapshotFreezer body_snapshot_freezer;
    static TransactionSnapshotFreezer txn_snapshot_freezer;

    switch (type) {
        case snapshots::headers:
            return header_snapshot_freezer;
        case snapshots::bodies:
            return body_snapshot_freezer;
        case snapshots::transactions:
            return txn_snapshot_freezer;
        default:
            assert(false);
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
            freezer.copy(db_tx, range, file_writer);
        }
        SnapshotFileWriter::flush(std::move(file_writer));
    }

    return std::make_shared<FreezerResult>(std::move(bundle));
}

void Freezer::index(std::shared_ptr<DataMigrationResult> result) {
    auto& freezer_result = dynamic_cast<FreezerResult&>(*result);
    auto& bundle = freezer_result.bundle;

    for (auto& snapshot_ref : bundle.snapshots()) {
        SnapshotPath snapshot_path = snapshot_ref.get().path();
        auto index_builders = snapshots_.bundle_factory().index_builders(snapshot_path);
        for (auto& index_builder : index_builders) {
            index_builder->build();
        }
    }
}

static void move_file(const std::filesystem::path& path, const std::filesystem::path& target_dir_path) {
    std::filesystem::rename(path, target_dir_path / path.filename());
}

void Freezer::commit(std::shared_ptr<DataMigrationResult> result) {
    auto& freezer_result = dynamic_cast<FreezerResult&>(*result);
    auto& bundle = freezer_result.bundle;

    for (auto& index_ref : bundle.indexes()) {
        move_file(index_ref.get().path().path(), snapshots_.path());
    }
    for (auto& snapshot_ref : bundle.snapshots()) {
        move_file(snapshot_ref.get().path().path(), snapshots_.path());
    }

    auto final_bundle = snapshots_.bundle_factory().make(snapshots_.path(), bundle.block_range());
    snapshots_.add_snapshot_bundle(std::move(final_bundle));
}

void Freezer::cleanup() {
    // TODO
}

}  // namespace silkworm::db
