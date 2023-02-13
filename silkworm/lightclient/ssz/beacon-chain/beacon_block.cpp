/*  beacon_block.cpp
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

#include "beacon_block.hpp"

namespace eth {

std::vector<ssz::Chunk> BeaconBlockBody::hash_tree() const {
    return hash_tree_({&randao_reveal,
                       &eth1_data,
                       &graffiti,
                       &proposer_slashings,
                       &attester_slashings,
                       &attestations,
                       &deposits,
                       &voluntary_exits,
                       &sync_aggregate,
                       &execution_payload});
}

BytesVector BeaconBlockBody::serialize() const {
    return serialize_({&randao_reveal,
                       &eth1_data,
                       &graffiti,
                       &proposer_slashings,
                       &attester_slashings,
                       &attestations,
                       &deposits,
                       &voluntary_exits,
                       &sync_aggregate,
                       &execution_payload});
}

bool BeaconBlockBody::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
    return deserialize_(it, end,
                        {&randao_reveal,
                         &eth1_data,
                         &graffiti,
                         &proposer_slashings,
                         &attester_slashings,
                         &attestations,
                         &deposits,
                         &voluntary_exits,
                         &sync_aggregate,
                         &execution_payload});
}

/*YAML::Node BeaconBlockBody::encode() const {
    return encode_({{"randao_reveal", &randao_reveal},
                    {"eth1_data", &eth1_data},
                    {"graffiti", &graffiti},
                    {"proposer_slashings", &proposer_slashings},
                    {"attester_slashings", &attester_slashings},
                    {"attestations", &attestations},
                    {"deposits", &deposits},
                    {"voluntary_exits", &voluntary_exits},
                    {"sync_aggregate", &sync_aggregate},
                    {"execution_payload", &execution_payload}});
}

bool BeaconBlockBody::decode(const YAML::Node &node) {
    return decode_(node, {{"randao_reveal", &randao_reveal},
                          {"eth1_data", &eth1_data},
                          {"graffiti", &graffiti},
                          {"proposer_slashings", &proposer_slashings},
                          {"attester_slashings", &attester_slashings},
                          {"attestations", &attestations},
                          {"deposits", &deposits},
                          {"voluntary_exits", &voluntary_exits},
                          {"sync_aggregate", &sync_aggregate},
                          {"execution_payload", &execution_payload}});
}*/

std::vector<ssz::Chunk> BeaconBlock::hash_tree() const {
    return hash_tree_({&slot, &proposer_index, &parent_root, &state_root, &body});
}

BytesVector BeaconBlock::serialize() const {
    return serialize_({&slot, &proposer_index, &parent_root, &state_root, &body});
}

bool BeaconBlock::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
    return deserialize_(it, end, {&slot, &proposer_index, &parent_root, &state_root, &body});
}

/*YAML::Node BeaconBlock::encode() const {
    return encode_({{"slot", &slot_},
                    {"proposer_index", &proposer_index_},
                    {"parent_root", &parent_root_},
                    {"state_root", &state_root_},
                    {"body", &body_}});
}

bool BeaconBlock::decode(const YAML::Node &node) {
    return decode_(node, {{"slot", &slot_},
                          {"proposer_index", &proposer_index_},
                          {"parent_root", &parent_root_},
                          {"state_root", &state_root_},
                          {"body", &body_}});
}*/

std::vector<ssz::Chunk> SignedBeaconBlock::hash_tree() const {
    return hash_tree_({&message, &signature});
}

BytesVector SignedBeaconBlock::serialize() const {
    return serialize_({&message, &signature});
}

bool SignedBeaconBlock::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
    return deserialize_(it, end, {&message, &signature});
}

/*YAML::Node SignedBeaconBlock::encode() const {
    return encode_({{"message", &message}, {"signature", &signature}});
}

bool SignedBeaconBlock::decode(const YAML::Node &node) {
    return decode_(node, {{"message", &message}, {"signature", &signature}});
}*/

}  // namespace eth
