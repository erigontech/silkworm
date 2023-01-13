/*  attestation.cpp
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

#include "attestation.hpp"

#include <algorithm>

namespace eth {
    std::vector<ssz::Chunk> AttestationData::hash_tree() const {
        return hash_tree_({&slot, &index, &beacon_block_root, &source, &target});
    }
    BytesVector AttestationData::serialize() const {
        return serialize_({&slot, &index, &beacon_block_root, &source, &target});
    }
    bool AttestationData::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
        return deserialize_(it, end, {&slot, &index, &beacon_block_root, &source, &target});
    }
    bool AttestationData::is_slashable(const AttestationData& rhs) const {
        if (*this != rhs && target.epoch == rhs.target.epoch) return true;
        return (source.epoch < rhs.source.epoch && target.epoch > rhs.target.epoch);
    }

    /*YAML::Node AttestationData::encode() const {
        return encode_({{"slot", &slot},
                        {"index", &index},
                        {"beacon_block_root", &beacon_block_root},
                        {"source", &source},
                        {"target", &target}});
    }

    bool AttestationData::decode(const YAML::Node &node) {
        return decode_(node, {{"slot", &slot},
                              {"index", &index},
                              {"beacon_block_root", &beacon_block_root},
                              {"source", &source},
                              {"target", &target}});
    }*/

    std::vector<ssz::Chunk> IndexedAttestation::hash_tree() const {
        return hash_tree_({&attesting_indices, &data, &signature});
    }
    BytesVector IndexedAttestation::serialize() const {
        return serialize_({&attesting_indices, &data, &signature});
    }

    bool IndexedAttestation::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
        return deserialize_(it, end, {&attesting_indices, &data, &signature});
    }
    bool IndexedAttestation::is_valid() const {
        if (!attesting_indices.size()) return false;
        if (!std::is_sorted(attesting_indices.cbegin(), attesting_indices.cend())) return false;
        const auto dup = std::adjacent_find(attesting_indices.cbegin(), attesting_indices.cend());
        return (dup == attesting_indices.cend());
    }

    /*YAML::Node IndexedAttestation::encode() const {
        return encode_({{"attesting_indices", &attesting_indices}, {"data", &data}, {"signature", &signature}});
    }

    bool IndexedAttestation::decode(const YAML::Node &node) {
        return decode_(node, {{"attesting_indices", &attesting_indices}, {"data", &data}, {"signature", &signature}});
    }*/

    std::vector<ssz::Chunk> PendingAttestation::hash_tree() const {
        return hash_tree_({&aggregation_bits, &data, &inclusion_delay, &proposer_index});
    }
    BytesVector PendingAttestation::serialize() const {
        return serialize_({&aggregation_bits, &data, &inclusion_delay, &proposer_index});
    }
    bool PendingAttestation::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
        return deserialize_(it, end, {&aggregation_bits, &data, &inclusion_delay, &proposer_index});
    }

    /*YAML::Node PendingAttestation::encode() const {
        return encode_({{"aggregation_bits", &aggregation_bits},
                        {"data", &data},
                        {"inclusion_delay", &inclusion_delay},
                        {"proposer_index", &proposer_index}});
    }

    bool PendingAttestation::decode(const YAML::Node &node) {
        return decode_(node, {{"aggregation_bits", &aggregation_bits},
                              {"data", &data},
                              {"inclusion_delay", &inclusion_delay},
                              {"proposer_index", &proposer_index}});
    }*/

    std::vector<ssz::Chunk> Attestation::hash_tree() const {
        return hash_tree_({&aggregation_bits, &data, &signature});
    }
    BytesVector Attestation::serialize() const {
        return serialize_({&aggregation_bits, &data, &signature});
    }
    bool Attestation::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
        return deserialize_(it, end, {&aggregation_bits, &data, &signature});
    }
    /*YAML::Node Attestation::encode() const {
        return encode_({{"aggregation_bits", &aggregation_bits}, {"data", &data}, {"signature", &signature}});
    }

    bool Attestation::decode(const YAML::Node &node) {
        return decode_(node, {{"aggregation_bits", &aggregation_bits}, {"data", &data}, {"signature", &signature}});
    }*/
}  // namespace eth
