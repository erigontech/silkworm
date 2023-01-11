/*  attestation.hpp
 *
 *  This file is part of Mammon.
 *  mammon is a greedy and selfish ETH consensus client.
 *
 *  Copyright (c) 2021 - Reimundo Heluani (potuz) potuz@potuz.net
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "silkworm/lightclient/ssz/common/bitlist.hpp"
#include "silkworm/lightclient/ssz/common/containers.hpp"
#include "silkworm/lightclient/ssz/config/constants.hpp"
#include "silkworm/lightclient/ssz/ssz/ssz.hpp"
// #include "yaml-cpp/yaml.h"

namespace eth {

struct AttestationData : public ssz::Container {
    Slot slot;
    CommitteeIndex index;

    Root beacon_block_root;
    Checkpoint source, target;

    static constexpr std::size_t ssz_size = 128;
    std::size_t get_ssz_size() const override { return ssz_size; }
    std::vector<ssz::Chunk> hash_tree() const override;
    BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;
    bool is_slashable(const AttestationData&) const;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

struct IndexedAttestation : public ssz::Container {
    ListFixedSizedParts<ValidatorIndex> attesting_indices{constants::MAX_VALIDATORS_PER_COMMITTEE};
    AttestationData data;
    BLSSignature signature;

    std::vector<ssz::Chunk> hash_tree() const override;
    BytesVector serialize() const override;
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

    std::vector<ssz::Chunk> hash_tree() const override;
    BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

struct Attestation : public ssz::Container {
    Bitlist aggregation_bits{constants::MAX_VALIDATORS_PER_COMMITTEE};
    AttestationData data;
    BLSSignature signature;

    std::vector<ssz::Chunk> hash_tree() const override;
    BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;
    
    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

}  // namespace eth
