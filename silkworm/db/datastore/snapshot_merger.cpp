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

#include <filesystem>
#include <memory>
#include <vector>

#include <silkworm/infra/common/filesystem.hpp>
#include <silkworm/infra/common/log.hpp>

#include "snapshots/common/raw_codec.hpp"
#include "snapshots/common/snapshot_path.hpp"
#include "snapshots/segment/seg/compressor.hpp"
#include "snapshots/segment/segment_writer.hpp"
#include "snapshots/snapshot_bundle.hpp"

namespace silkworm::datastore {

using namespace silkworm::snapshots;

struct SnapshotMergerCommand : public DataMigrationCommand {
    BlockNumRange range;

    explicit SnapshotMergerCommand(BlockNumRange range1)
        : range(range1) {}
    ~SnapshotMergerCommand() override = default;

    std::string description() const override {
        std::stringstream stream;
        stream << "SnapshotMergerCommand " << range.to_string();
        return stream.str();
    }
};

struct SnapshotMergerResult : public DataMigrationResult {
    SnapshotBundlePaths bundle_paths;

    explicit SnapshotMergerResult(SnapshotBundlePaths bundle_paths1)
        : bundle_paths(std::move(bundle_paths1)) {}
    ~SnapshotMergerResult() override = default;
};

std::unique_ptr<DataMigrationCommand> SnapshotMerger::next_command() {
    BlockNum first_block_num = 0;
    size_t block_count = 0;
    size_t batch_size = 0;

    for (auto& bundle_ptr : snapshots_.view_bundles()) {
        auto& bundle = *bundle_ptr;

        auto bundle_block_num_range = snapshots_.step_converter().timestamp_range_from_step_range(bundle.step_range());
        size_t bundle_block_count = bundle_block_num_range.size();

        if (bundle_block_count >= kMaxSnapshotSize) {
            continue;
        }
        if (bundle_block_count != block_count) {
            first_block_num = bundle_block_num_range.start;
            block_count = bundle_block_count;
            batch_size = 0;
        }
        ++batch_size;
        if (batch_size == kBatchSize) {
            return std::make_unique<SnapshotMergerCommand>(BlockNumRange{first_block_num, bundle_block_num_range.end});
        }
    }

    return {};
}

std::shared_ptr<DataMigrationResult> SnapshotMerger::migrate(std::unique_ptr<DataMigrationCommand> command) {
    auto& merger_command = dynamic_cast<SnapshotMergerCommand&>(*command);
    auto range = merger_command.range;
    StepRange step_range = snapshots_.step_converter().step_range_from_timestamp_range({range.start, range.end});

    SnapshotBundlePaths new_bundle{snapshots_.schema(), tmp_dir_path_, step_range};
    for (const auto& [name, path] : new_bundle.segment_paths()) {
        SILK_DEBUG_M("SnapshotMerger") << "merging " << name.to_string() << " range " << range.to_string();
        seg::Compressor compressor{path.path(), tmp_dir_path_};

        for (auto& bundle_ptr : snapshots_.bundles_in_range(step_range)) {
            auto& bundle = *bundle_ptr;
            segment::SegmentReader<RawDecoder<Bytes>> reader{bundle.segment(Schema::kDefaultEntityName, name)};
            std::copy(reader.begin(), reader.end(), compressor.add_word_iterator());
        }

        seg::Compressor::compress(std::move(compressor));
    }

    return std::make_shared<SnapshotMergerResult>(std::move(new_bundle));
}

void SnapshotMerger::index(std::shared_ptr<DataMigrationResult> result) {
    auto& merger_result = dynamic_cast<SnapshotMergerResult&>(*result);
    snapshots_.build_indexes(merger_result.bundle_paths);
}

static void schedule_bundle_cleanup(SnapshotBundle& bundle) {
    // NOLINTNEXTLINE(performance-unnecessary-value-param)
    bundle.on_close([](std::vector<std::filesystem::path> files) {
        for (auto& path : files) {
            [[maybe_unused]] bool removed = std::filesystem::remove(path);
        }
    });
}

void SnapshotMerger::commit(std::shared_ptr<DataMigrationResult> result) {
    auto& freezer_result = dynamic_cast<SnapshotMergerResult&>(*result);
    auto& bundle = freezer_result.bundle_paths;
    auto merged_bundles = snapshots_.bundles_in_range(bundle.step_range());

    move_files(bundle.files(), snapshots_.path());

    SnapshotBundle final_bundle = snapshots_.open_bundle(bundle.step_range());
    snapshots_.replace_snapshot_bundles(std::move(final_bundle));

    for (auto& merged_bundle : merged_bundles) {
        schedule_bundle_cleanup(*merged_bundle);
    }

    on_snapshot_merged_signal_(bundle.step_range());
}

boost::signals2::scoped_connection SnapshotMerger::on_snapshot_merged(const std::function<void(StepRange)>& callback) {
    return on_snapshot_merged_signal_.connect(callback);
}

Task<void> SnapshotMerger::cleanup() {
    // the cleanup happens when bundle readers stop using them
    co_return;
}

}  // namespace silkworm::datastore
