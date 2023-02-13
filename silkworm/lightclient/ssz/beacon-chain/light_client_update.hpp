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

#include <silkworm/lightclient/ssz/constants.hpp>
#include <silkworm/lightclient/ssz/ssz_container.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/beacon_block.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/sync_aggregate.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/sync_committee.hpp>
#include <silkworm/lightclient/ssz/common/containers.hpp>
#include <silkworm/lightclient/ssz/common/slot.hpp>

namespace eth {
class LightClientUpdate : public ssz::Container {
  private:
    BeaconBlockHeader attested_header_;
    SyncCommittee next_sync_committee_;
    VectorFixedSizedParts<Hash32, constants::kSyncCommitteeBranchSize> next_sync_committee_branch_;
    BeaconBlockHeader finalized_header_;
    VectorFixedSizedParts<Hash32, constants::kFinalityBranchSize> finality_branch_;
    SyncAggregate sync_aggregate_;
    Slot signature_slot_;

  public:
    [[nodiscard]] const auto& attested_header() const { return attested_header_; }
    [[nodiscard]] const auto& next_sync_committee() const { return next_sync_committee_; }
    [[nodiscard]] const auto& next_sync_committee_branch() const { return next_sync_committee_branch_; }
    [[nodiscard]] const auto& finalized_header() const { return finalized_header_; }
    [[nodiscard]] const auto& finality_branch() const { return finality_branch_; }
    [[nodiscard]] const auto& sync_aggregate() const { return sync_aggregate_; }
    [[nodiscard]] const auto& signature_slot() const { return signature_slot_; }

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};
}  // namespace eth
