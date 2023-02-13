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

#include "sync_committee.hpp"

namespace eth {
    std::vector<ssz::Chunk> SyncCommittee::hash_tree() const {
        return hash_tree_({&pubkeys_, &aggregate_pubkey_});
    }
    BytesVector SyncCommittee::serialize() const {
        return serialize_({&pubkeys_, &aggregate_pubkey_});
    }

    bool SyncCommittee::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
        return deserialize_(it, end, {&pubkeys_, &aggregate_pubkey_});
    }

    /*YAML::Node SyncCommittee::encode() const {
        return encode_({{"pubkeys", &pubkeys_}, {"aggregate_pubkey", &aggregate_pubkey_}});
    }
    bool SyncCommittee::decode(const YAML::Node &node) {
        return decode_(node, {{"pubkeys", &pubkeys_}, {"aggregate_pubkey", &aggregate_pubkey_}});
    }*/
} // namespace eth
