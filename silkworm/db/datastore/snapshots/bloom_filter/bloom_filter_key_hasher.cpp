/*
   Copyright 2024 The Silkworm Authors

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

#include "bloom_filter_key_hasher.hpp"

#include <array>

#include "../common/encoding/murmur_hash3.hpp"

namespace silkworm::snapshots::bloom_filter {

uint64_t BloomFilterKeyHasher::hash(ByteView key) const {
    std::array<uint64_t, 2> hash = {0, 0};
    encoding::Murmur3{salt_}.hash_x64_128(key.data(), key.size(), hash.data());
    return hash[0];
}

}  // namespace silkworm::snapshots::bloom_filter
