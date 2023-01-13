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

#include "beacon_block_header.hpp"

namespace eth {

std::vector<ssz::Chunk> BeaconBlockHeader::hash_tree() const {
    return hash_tree_({&slot, &proposer_index, &parent_root, &state_root, &body_root});
}

BytesVector BeaconBlockHeader::serialize() const {
    return serialize_({&slot, &proposer_index, &parent_root, &state_root, &body_root});
}

bool BeaconBlockHeader::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
    return deserialize_(it, end, {&slot, &proposer_index, &parent_root, &state_root, &body_root});
}

/*YAML::Node BeaconBlockHeader::encode() const {
    return encode_({{"slot", &slot},
                    {"proposer_index", &proposer_index},
                    {"parent_root", &parent_root},
                    {"state_root", &state_root},
                    {"body_root", &body_root}});
}

bool BeaconBlockHeader::decode(const YAML::Node &node) {
    return decode_(node, {{"slot", &slot},
                          {"proposer_index", &proposer_index},
                          {"parent_root", &parent_root},
                          {"state_root", &state_root},
                          {"body_root", &body_root}});
}*/

std::vector<ssz::Chunk> SignedBeaconBlockHeader::hash_tree() const {
    return hash_tree_({&message, &signature});
}

BytesVector SignedBeaconBlockHeader::serialize() const {
    return serialize_({&message, &signature});
}

bool SignedBeaconBlockHeader::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
    return deserialize_(it, end, {&message, &signature});
}

/*YAML::Node SignedBeaconBlockHeader::encode() const override { return encode_({{"message", &message}, {"signature", &signature}}); }

bool SignedBeaconBlockHeader::decode(const YAML::Node &node) override {
    return decode_(node, {{"message", &message}, {"signature", &signature}});
}*/

}  // namespace eth
