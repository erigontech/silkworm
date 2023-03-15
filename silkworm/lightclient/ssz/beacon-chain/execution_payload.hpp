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

//! Execution payload is sent to EL once validation is done to request block execution.
struct ExecutionPayload : public ssz::Container {
    Hash32 parent_hash;
    Eth1Address fee_recipient;
    Root state_root;
    Root receipts_root;
    Bytes256 logs_bloom;
    Hash32 prev_randao;
    Counter block_number;
    Counter gas_limit;
    Counter gas_used;
    UnixTime timestamp;
    ListFixedSizedParts<Byte> extra_data;
    VectorFixedSizedParts<Byte, constants::kSlotsPerEpoch> base_fee_per_gas;
    Hash32 block_hash;
    ListVariableSizedParts<ListFixedSizedParts<Byte>> transactions;

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

}  // namespace eth
