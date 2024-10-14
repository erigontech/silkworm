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

#include "config.hpp"

#include <span>

#include <boost/algorithm/string.hpp>

#include <silkworm/core/common/small_map.hpp>

#include "config/amoy.hpp"
#include "config/bor_mainnet.hpp"
#include "config/holesky.hpp"
#include "config/mainnet.hpp"
#include "config/sepolia.hpp"
#include "snapshot_path.hpp"
#include "snapshot_size.hpp"

namespace silkworm::snapshots {

inline constexpr SmallMap<ChainId, std::span<const Entry>> kKnownConfigGeneratedEntries{
    {*kKnownChainNameToId.find("mainnet"sv), {kMainnetSnapshots.data(), kMainnetSnapshots.size()}},
    {*kKnownChainNameToId.find("sepolia"sv), {kSepoliaSnapshots.data(), kSepoliaSnapshots.size()}},
    {*kKnownChainNameToId.find("holesky"sv), {kHoleskySnapshots.data(), kHoleskySnapshots.size()}},
    {*kKnownChainNameToId.find("bor-mainnet"sv), {kBorMainnetSnapshots.data(), kBorMainnetSnapshots.size()}},
    {*kKnownChainNameToId.find("amoy"sv), {kAmoySnapshots.data(), kAmoySnapshots.size()}},
};

Config Config::lookup_known_config(ChainId chain_id) {
    const auto entries_ptr = kKnownConfigGeneratedEntries.find(chain_id);
    if (!entries_ptr) {
        return Config{PreverifiedList{}};
    }

    PreverifiedList entries(entries_ptr->begin(), entries_ptr->end());
    entries = remove_unsupported_snapshots(entries);

    return Config{std::move(entries)};
}

Config::Config(PreverifiedList entries)
    : entries_(std::move(entries)),
      max_block_number_(compute_max_block(entries_)) {
}

BlockNum Config::compute_max_block(const PreverifiedList& entries) {
    BlockNum max_block{0};
    for (const auto& entry : entries) {
        const auto snapshot_path = SnapshotPath::parse(std::filesystem::path{entry.file_name});
        if (!snapshot_path) continue;
        if (snapshot_path->extension() != kSegmentExtension) continue;
        if (snapshot_path->type() != SnapshotType::headers) continue;
        if (snapshot_path->block_range().end > max_block) {
            max_block = snapshot_path->block_range().end;
        }
    }
    return max_block > 0 ? max_block - 1 : 0;
}

PreverifiedList Config::remove_unsupported_snapshots(const PreverifiedList& entries) {
    static constexpr std::array kUnsupportedSnapshotNameTokens = {
        "accessor/"sv, "domain/"sv, "history/"sv, "idx/"sv, "manifest.txt"sv, "salt-blocks.txt"sv, "salt-state.txt"sv, "blobsidecars.seg"sv};

    PreverifiedList results = entries;

    // Check if a snapshot contains any of unsupported tokens
    std::erase_if(results, [&](const auto& entry) {
        return std::any_of(kUnsupportedSnapshotNameTokens.begin(), kUnsupportedSnapshotNameTokens.end(), [&entry](const auto& token) {
            return boost::algorithm::contains(entry.file_name, token);
        });
    });

    // Exclude small snapshots
    std::erase_if(results, [&](const auto& entry) {
        const auto snapshot_path = SnapshotPath::parse(std::filesystem::path{entry.file_name});
        return !snapshot_path.has_value() || (snapshot_path->block_range().size() < kMaxMergerSnapshotSize);
    });

    return results;
}

}  // namespace silkworm::snapshots
