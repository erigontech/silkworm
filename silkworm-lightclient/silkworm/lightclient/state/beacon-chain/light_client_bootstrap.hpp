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

#include <silkworm/lightclient/ssz/common/boolean.hpp>
#include <silkworm/lightclient/ssz/common/containers.hpp>
#include <silkworm/lightclient/ssz/common/slot.hpp>
#include <silkworm/lightclient/ssz/config/constants.hpp>
#include <silkworm/lightclient/ssz/ssz/ssz_container.hpp>
#include <silkworm/lightclient/state/beacon-chain/beacon_block.hpp>
#include <silkworm/lightclient/state/beacon-chain/sync_committee.hpp>

namespace eth {
class LightClientBootstrap : public ssz::Container {
  private:
    BeaconBlockHeader header_;
    SyncCommittee current_sync_committee_;
    VectorFixedSizedParts<Hash32, constants::kSyncCommitteeBranchSize> current_sync_committee_branch_;

  public:
    [[nodiscard]] const auto& header() const { return header_; }
    [[nodiscard]] const auto& current_sync_committee() const { return current_sync_committee_; }
    [[nodiscard]] const auto& current_sync_committee_branch() const { return current_sync_committee_branch_; }

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};
}  // namespace eth
