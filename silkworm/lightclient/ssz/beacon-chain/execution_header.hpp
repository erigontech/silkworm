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
#include <silkworm/lightclient/ssz/common/containers.hpp>
#include <silkworm/lightclient/ssz/common/slot.hpp>

namespace eth {
class ExecutionHeader : public ssz::Container {
  private:
    Hash32 parent_hash_;
    Eth1Address fee_recipient_;
    Root state_root_;
    Root receipts_root_;
    Bytes256 logs_bloom_;
    Hash32 prev_randao_;
    Counter block_number_;
    Counter gas_limit_;
    Counter gas_used_;
    UnixTime timestamp_;
    ListFixedSizedParts<Byte> extra_data_;
    VectorFixedSizedParts<Byte, constants::SLOTS_PER_EPOCH> base_fee_per_gas_;
    Hash32 block_hash_;
    Root transient_root_;

  public:
    [[nodiscard]] const auto& parent_hash() const { return parent_hash_; }
    [[nodiscard]] const auto& fee_recipient() const { return fee_recipient_; }
    [[nodiscard]] const auto& state_root() const { return state_root_; }
    [[nodiscard]] const auto& receipts_root() const { return receipts_root_; }
    [[nodiscard]] const auto& logs_bloom() const { return logs_bloom_; }
    [[nodiscard]] const auto& prev_randao() const { return prev_randao_; }
    [[nodiscard]] const auto& block_number() const { return block_number_; }
    [[nodiscard]] const auto& gas_limit() const { return gas_limit_; }
    [[nodiscard]] const auto& gas_used() const { return gas_used_; }
    [[nodiscard]] const auto& timestamp() const { return timestamp_; }
    [[nodiscard]] const auto& extra_data() const { return extra_data_; }
    [[nodiscard]] const auto& base_fee_per_gas() const { return base_fee_per_gas_; }
    [[nodiscard]] const auto& block_hash() const { return block_hash_; }
    [[nodiscard]] const auto& transient_root() const { return transient_root_; }

    std::vector<ssz::Chunk> hash_tree() const override;
    BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};
}  // namespace eth
