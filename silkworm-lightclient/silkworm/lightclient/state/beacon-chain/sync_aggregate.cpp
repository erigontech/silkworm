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

#include "sync_aggregate.hpp"

namespace eth {
    std::vector<ssz::Chunk> SyncAggregate::hash_tree() const {
        return hash_tree_({&sync_committee_bits_,
                           &sync_committee_signature_});
    }
    BytesVector SyncAggregate::serialize() const {
        return serialize_({&sync_committee_bits_,
                           &sync_committee_signature_});
    }

    bool SyncAggregate::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
        return deserialize_(it, end, {&sync_committee_bits_,
                                      &sync_committee_signature_});
    }

    /*YAML::Node SyncAggregate::encode() const {
        return encode_({{"sync_committee_bits", &sync_committee_bits_},
                        {"sync_committee_signature", &sync_committee_signature_}});
    }
    bool SyncAggregate::decode(const YAML::Node &node) {
        return decode_(node, {{"sync_committee_bits", &sync_committee_bits_},
                              {"sync_committee_signature", &sync_committee_signature_}});
    }*/
} // namespace eth
