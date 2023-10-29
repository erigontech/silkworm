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

#include <algorithm>
#include <map>
#include <utility>

#include <toml.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/snapshot/config_toml.hpp>
#include <silkworm/node/snapshot/path.hpp>

namespace silkworm::snapshot {

PreverifiedList from_toml(std::string_view preverified_toml_doc) {
    const auto table = toml::parse(preverified_toml_doc);
    SILK_DEBUG << "from_toml #size: " << preverified_toml_doc.size() << " #snapshots: " << table.size();

    PreverifiedList preverified;
    preverified.reserve(table.size());
    for (auto&& [key, value] : table) {
        preverified.emplace_back(PreverifiedEntry{{key.begin(), key.end()}, value.as_string()->get()});
    }
    std::sort(preverified.begin(), preverified.end(), [](auto& p1, auto& p2) { return p1.file_name < p2.file_name; });

    std::for_each(preverified.begin(), preverified.end(), [](auto& p) {
        SILK_DEBUG << "name: " << p.file_name << " hash: " << p.torrent_hash;
    });

    return preverified;
}

const Config Config::kGoerliSnapshotConfig{from_toml({goerli_toml_data(), goerli_toml_size()})};
const Config Config::kMainnetSnapshotConfig{from_toml({mainnet_toml_data(), mainnet_toml_size()})};
const Config Config::kSepoliaSnapshotConfig{from_toml({sepolia_toml_data(), sepolia_toml_size()})};

const std::map<uint64_t, const Config*> Config::kKnownSnapshotConfigs{
    {kGoerliConfig.chain_id, &kGoerliSnapshotConfig},
    {kMainnetConfig.chain_id, &kMainnetSnapshotConfig},
    {kSepoliaConfig.chain_id, &kSepoliaSnapshotConfig},
    // TODO(yperbasis): add Polygon
};

struct NullDeleter {
    void operator()(void const*) const {}
};

std::shared_ptr<const Config> Config::lookup_known_config(uint64_t chain_id, const std::vector<std::string>& whitelist) {
    const auto config_it = kKnownSnapshotConfigs.find(chain_id);
    if (config_it == kKnownSnapshotConfigs.end()) {
        return std::make_shared<Config>(PreverifiedList{});
    }
    if (whitelist.empty()) {
        return std::shared_ptr<const Config>{config_it->second, NullDeleter{}};
    }

    PreverifiedList filtered_preverified;
    for (const auto& preverified_entry : config_it->second->preverified_snapshots()) {
        if (std::find(whitelist.cbegin(), whitelist.cend(), preverified_entry.file_name) != whitelist.cend()) {
            filtered_preverified.push_back(preverified_entry);
        }
    }
    return std::make_shared<Config>(filtered_preverified);
}

Config::Config(PreverifiedList preverified_snapshots)
    : preverified_snapshots_(std::move(preverified_snapshots)), max_block_number_(compute_max_block()) {
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

}  // namespace silkworm::snapshot
