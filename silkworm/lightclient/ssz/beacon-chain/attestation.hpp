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
#include <silkworm/lightclient/ssz/common/bitlist.hpp>
#include <silkworm/lightclient/ssz/common/containers.hpp>
// #include "yaml-cpp/yaml.h"

namespace eth {

struct AttestationData : public ssz::Container {
    Slot slot;
    CommitteeIndex index;

    Root beacon_block_root;
    Checkpoint source, target;

    static constexpr std::size_t ssz_size = 128;
    [[nodiscard]] std::size_t get_ssz_size() const override { return ssz_size; }
    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;
    bool is_slashable(const AttestationData&) const;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

struct IndexedAttestation : public ssz::Container {
    ListFixedSizedParts<ValidatorIndex> attesting_indices{constants::MAX_VALIDATORS_PER_COMMITTEE};
    AttestationData data;
    BLSSignature signature;

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;
    bool is_valid() const;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

struct PendingAttestation : public ssz::Container {
    Bitlist aggregation_bits{constants::MAX_VALIDATORS_PER_COMMITTEE};
    AttestationData data;
    Slot inclusion_delay;
    ValidatorIndex proposer_index;

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

struct Attestation : public ssz::Container {
    Bitlist aggregation_bits{constants::MAX_VALIDATORS_PER_COMMITTEE};
    AttestationData data;
    BLSSignature signature;

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;
    
    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

}  // namespace eth
