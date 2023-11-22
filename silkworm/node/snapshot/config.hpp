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

#pragma once

#include <span>
#include <string>
#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/small_map.hpp>
#include <silkworm/node/snapshot/config/bor_mainnet.hpp>
#include <silkworm/node/snapshot/config/goerli.hpp>
#include <silkworm/node/snapshot/config/mainnet.hpp>
#include <silkworm/node/snapshot/config/mumbai.hpp>
#include <silkworm/node/snapshot/config/sepolia.hpp>
#include <silkworm/node/snapshot/entry.hpp>

namespace silkworm::snapshot {

using PreverifiedList = std::vector<Entry>;

class Config {
  public:
    static Config lookup_known_config(ChainId chain_id, const std::vector<std::string>& whitelist);

    explicit Config(PreverifiedList preverified_snapshots);

    [[nodiscard]] const PreverifiedList& preverified_snapshots() const { return preverified_snapshots_; }
    [[nodiscard]] BlockNum max_block_number() const { return max_block_number_; }

  private:
    BlockNum compute_max_block();

    PreverifiedList preverified_snapshots_;
    BlockNum max_block_number_;
};

inline constexpr SmallMap<ChainId, std::span<const Entry>> kKnownSnapshotConfigs{
    {*kKnownChainNameToId.find("mainnet"sv), {kMainnetSnapshots.data(), kMainnetSnapshots.size()}},
    {*kKnownChainNameToId.find("goerli"sv), {kGoerliSnapshots.data(), kGoerliSnapshots.size()}},
    {*kKnownChainNameToId.find("sepolia"sv), {kSepoliaSnapshots.data(), kSepoliaSnapshots.size()}},
    {*kKnownChainNameToId.find("polygon"sv), {kBorMainnetSnapshots.data(), kBorMainnetSnapshots.size()}},
    {*kKnownChainNameToId.find("mumbai"sv), {kMumbaiSnapshots.data(), kMumbaiSnapshots.size()}},
};

}  // namespace silkworm::snapshot
