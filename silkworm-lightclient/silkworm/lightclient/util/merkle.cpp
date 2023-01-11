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

#include "merkle.hpp"

#include <string>

#include <keccak.h>

#include <silkworm/common/base.hpp>
#include <silkworm/common/util.hpp>

namespace silkworm::cl {

bool is_valid_merkle_branch(const Hash32& leaf, const Hash32Sequence& branch, uint64_t depth, uint64_t index,
                            const Hash32& root) {
    static Keccak keccak256;

    std::string value{leaf.bytes, leaf.bytes + kHashLength};
    for (uint64_t i{0}; i < depth; ++i) {
        keccak256.reset();
        if (index / 1 << i % 2 == 1) {
            keccak256.add(branch[i].bytes, kHashLength);
            keccak256.add(value.data(), kHashLength);
        } else {
            keccak256.add(value.data(), kHashLength);
            keccak256.add(branch[i].bytes, kHashLength);
        }
        value = keccak256.getHash();
    }
    return to_bytes32(Bytes{value.begin(), value.end()}) == root;
}

}  // namespace silkworm::cl
