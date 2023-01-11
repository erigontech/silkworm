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

#include "storage.hpp"

#include "silkworm/common/util.hpp"
#include "silkworm/lightclient/util/merkle.hpp"

namespace silkworm::cl {

Storage::Storage(const Hash32& trusted_root, const cl::LightClientBootstrap& bootstrap) {
    const auto header_root = bootstrap.header->hash_tree_root();
    if (header_root != trusted_root) {
        throw std::runtime_error{"root mismatch: trusted_root=" + to_hex(trusted_root) +
                                 " header_root=" + to_hex(header_root)};
    }
    const auto sync_committee_root = bootstrap.current_committee->hash_tree_root();
    const auto& current_committee_branch = bootstrap.current_committee_branch;
    if (!is_valid_merkle_branch(sync_committee_root, current_committee_branch, 5, 22, bootstrap.header->root)) {
        throw std::runtime_error{"invalid sync committee"};
    }
    finalized_header_ = bootstrap.header;
    current_committee_ = bootstrap.current_committee;
    optimistic_header_ = bootstrap.header;
}

}  // namespace silkworm::cl
