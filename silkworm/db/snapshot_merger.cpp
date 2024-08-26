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

#include "snapshot_merger.hpp"

#include <algorithm>

#include <silkworm/infra/common/filesystem.hpp>
#include <silkworm/infra/common/log.hpp>

#include "snapshots/path.hpp"
#include "snapshots/seg/compressor.hpp"
#include "snapshots/snapshot_bundle.hpp"
#include "snapshots/snapshot_writer.hpp"

namespace silkworm::db {

using namespace silkworm::snapshots;

struct SnapshotMergerCommand : public DataMigrationCommand {
    BlockNumRange range;

    explicit SnapshotMergerCommand(BlockNumRange range1)
        : range(std::move(range1)) {}
    ~SnapshotMergerCommand() override = default;

    std::string description() const override {
        std::stringstream stream;
        stream << "SnapshotMergerCommand [" << range.first << ", " << range.second << ")";
        return stream.str();
    }
};

struct SnapshotMergerResult : public DataMigrationResult {
    SnapshotBundle bundle;

    explicit SnapshotMergerResult(SnapshotBundle bundle1)
        : bundle(std::move(bundle1)) {}
    ~SnapshotMergerResult() override = default;
};

std::unique_ptr<DataMigrationCommand> SnapshotMerger::next_command() {
    BlockNum first_block_num = 0;
    size_t block_count = 0;
    size_t batch_size = 0;

    for (auto& bundle_ptr : snapshots_.view_bundles()) {
        auto& bundle = *bundle_ptr;
        if (bundle.block_count() >= kMaxSnapshotSize) {
            continue;
        }
        if (bundle.block_count() != block_count) {
            first_block_num = bundle.block_from();
            block_count = bundle.block_count();
            batch_size = 0;
        }
        batch_size++;
        if (batch_size == kBatchSize) {
            return std::make_unique<SnapshotMergerCommand>(BlockNumRange{first_block_num, bundle.block_to()});
        }
    }

    return {};
}

struct RawSnapshotWordDeserializer : public SnapshotWordDeserializer {
    ByteView value;
    ~RawSnapshotWordDeserializer() override = default;
    void decode_word(ByteView word) override {
        value = word;
    }
};

std::shared_ptr<DataMigrationResult> SnapshotMerger::migrate(std::unique_ptr<DataMigrationCommand> command) {
    auto& merger_command = dynamic_cast<SnapshotMergerCommand&>(*command);
    auto range = merger_command.range;
    auto range_contains = [range](BlockNum num) -> bool {
        return (range.first <= num) && (num < range.second);
    };

    auto new_bundle = snapshots_.bundle_factory().make(tmp_dir_path_, range);
    for (auto& snapshot_ref : new_bundle.snapshots()) {
        auto path = snapshot_ref.get().path();
        log::Debug("SnapshotMerger") << "merging " << path.type_string() << " range [" << range.first << ", " << range.second << ")";
        seg::Compressor compressor{path.path(), tmp_dir_path_};

        for (auto& bundle_ptr : snapshots_.view_bundles()) {
            auto& bundle = *bundle_ptr;
            if (!range_contains(bundle.block_from())) continue;

            SnapshotReader<RawSnapshotWordDeserializer> reader{bundle.snapshot(path.type())};
            std::copy(reader.begin(), reader.end(), compressor.add_word_iterator());
        }

        seg::Compressor::compress(std::move(compressor));
    }

    return std::make_shared<SnapshotMergerResult>(std::move(new_bundle));
}

void SnapshotMerger::index(std::shared_ptr<DataMigrationResult> result) {
    auto& merger_result = dynamic_cast<SnapshotMergerResult&>(*result);
    auto& bundle = merger_result.bundle;
    snapshots_.build_indexes(bundle);
}

void SnapshotMerger::commit(std::shared_ptr<DataMigrationResult> result) {
    auto& freezer_result = dynamic_cast<SnapshotMergerResult&>(*result);
    auto& bundle = freezer_result.bundle;
    move_files(bundle.files(), snapshots_.path());

    auto final_bundle = snapshots_.bundle_factory().make(snapshots_.path(), bundle.block_range());
    snapshots_.replace_snapshot_bundles(std::move(final_bundle));
}

Task<void> SnapshotMerger::cleanup() {
    // TODO
    co_return;
}

BlockNumRange SnapshotMerger::cleanup_range() {
    // TODO
    return BlockNumRange{0, 0};
}

}  // namespace silkworm::db
