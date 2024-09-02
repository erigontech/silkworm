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

#include <map>
#include <utility>

#include <boost/algorithm/string.hpp>

#include <silkworm/db/snapshots/snapshot_path.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots {

Config Config::lookup_known_config(ChainId chain_id, const std::vector<std::string>& whitelist) {
    const auto config = kKnownSnapshotConfigs.find(chain_id);
    if (!config) {
        return Config{PreverifiedList{}};
    }
    if (whitelist.empty()) {
        return Config{PreverifiedList(config->begin(), config->end())};
    }

    PreverifiedList filtered_preverified;
    for (const auto& preverified_entry : *config) {
        if (std::find(whitelist.cbegin(), whitelist.cend(), preverified_entry.file_name) != whitelist.cend()) {
            filtered_preverified.push_back(preverified_entry);
        }
    }
    return Config{filtered_preverified};
}

Config::Config(PreverifiedList preverified_snapshots)
    : preverified_snapshots_(std::move(preverified_snapshots)), max_block_number_(compute_max_block()) {
    remove_unsupported_snapshots();
}

BlockNum Config::compute_max_block() {
    BlockNum max_block{0};
    for (const auto& preverified_entry : preverified_snapshots_) {
        const auto snapshot_path = SnapshotPath::parse(std::filesystem::path{preverified_entry.file_name});
        if (!snapshot_path) continue;
        if (!snapshot_path->is_segment()) continue;
        if (snapshot_path->type() != SnapshotType::headers) continue;
        if (snapshot_path->block_to() > max_block) {
            max_block = snapshot_path->block_to();
        }
    }
    return max_block > 0 ? max_block - 1 : 0;
}

void Config::remove_unsupported_snapshots() {
    static constexpr std::array kUnsupportedSnapshotNameTokens = {
        "accessor/"sv, "domain/"sv, "history/"sv, "idx/"sv, "manifest.txt"sv, "salt-blocks.txt"sv, "salt-state.txt"sv, "blobsidecars.seg"sv};

    // Check if a snapshot contains any of unsupported tokens
    std::erase_if(preverified_snapshots_, [&](const auto& snapshot) {
        return std::any_of(kUnsupportedSnapshotNameTokens.begin(), kUnsupportedSnapshotNameTokens.end(), [&snapshot](const auto& token) {
            return boost::algorithm::contains(snapshot.file_name, token);
        });
    });
}

}  // namespace silkworm::snapshots
