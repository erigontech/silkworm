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

#include "light_client_update.hpp"

namespace eth {
    std::vector<ssz::Chunk> LightClientUpdate::hash_tree() const {
        return hash_tree_({&attested_header_,
                           &next_sync_committee_,
                           &next_sync_committee_branch_,
                           &finalized_header_,
                           &finality_branch_,
                           &sync_aggregate_,
                           &signature_slot_});
    }
    BytesVector LightClientUpdate::serialize() const {
        return serialize_({&attested_header_,
                           &next_sync_committee_,
                           &next_sync_committee_branch_,
                           &finalized_header_,
                           &finality_branch_,
                           &sync_aggregate_,
                           &signature_slot_});
    }

    bool LightClientUpdate::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
        return deserialize_(it, end, {&attested_header_,
                                      &next_sync_committee_,
                                      &next_sync_committee_branch_,
                                      &finalized_header_,
                                      &finality_branch_,
                                      &sync_aggregate_,
                                      &signature_slot_});
    }

    /*YAML::Node LightClientUpdate::encode() const {
        return encode_({{"attested_header", &attested_header_},
                        {"next_sync_committee", &next_sync_committee_},
                        {"next_sync_committee_branch", &next_sync_committee_branch_},
                        {"finalized_header", &finalized_header_},
                        {"finality_branch", &finality_branch_},
                        {"sync_aggregate", &sync_aggregate_},
                        {"signature_slot", &signature_slot_}});
    }
    bool LightClientUpdate::decode(const YAML::Node &node) {
        return decode_(node, {{"attested_header", &attested_header_},
                              {"next_sync_committee", &next_sync_committee_},
                              {"next_sync_committee_branch", &next_sync_committee_branch_},
                              {"finalized_header", &finalized_header_},
                              {"finality_branch", &finality_branch_},
                              {"sync_aggregate", &sync_aggregate_},
                              {"signature_slot", &signature_slot_}});
    }*/
} // namespace eth
