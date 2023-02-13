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

#include <silkworm/lightclient/ssz/chunk.hpp>
#include <silkworm/lightclient/ssz/constants.hpp>
#include <silkworm/lightclient/ssz/ssz_container.hpp>
#include <silkworm/lightclient/ssz/common/containers.hpp>
#include <silkworm/lightclient/ssz/common/slot.hpp>

namespace eth {

//! \brief Determine successful committee: bits shows active participants and signature is the aggregate BLS signature
struct SyncAggregate : public ssz::Container {
    VectorFixedSizedParts<Byte, constants::kCommiteeBitsSize> sync_committee_bits;
    BLSSignature sync_committee_signature;

    [[nodiscard]] std::size_t get_ssz_size() const override {
        return sync_committee_bits.get_ssz_size() + sync_committee_signature.get_ssz_size();
    }
    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

}  // namespace eth
