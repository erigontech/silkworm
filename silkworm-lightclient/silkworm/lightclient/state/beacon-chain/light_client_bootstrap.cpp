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

#include "light_client_bootstrap.hpp"

namespace eth {
    std::vector<ssz::Chunk> LightClientBootstrap::hash_tree() const {
        return hash_tree_({&header_,
                           &current_sync_committee_,
                           &current_sync_committee_branch_});
    }
    BytesVector LightClientBootstrap::serialize() const {
        return serialize_({&header_,
                           &current_sync_committee_,
                           &current_sync_committee_branch_});
    }

    bool LightClientBootstrap::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
        return deserialize_(it, end, {&header_,
                                      &current_sync_committee_,
                                      &current_sync_committee_branch_});
    }

    /*YAML::Node LightClientBootstrap::encode() const {
        return encode_({{"header", &header_},
                        {"current_sync_committee", &current_sync_committee_},
                        {"current_sync_committee_branch", &current_sync_committee_branch_}});
    }
    bool LightClientBootstrap::decode(const YAML::Node &node) {
        return decode_(node, {{"header", &header_},
                              {"current_sync_committee", &current_sync_committee_},
                              {"current_sync_committee_branch", &current_sync_committee_branch_}});
    }*/
} // namespace eth
