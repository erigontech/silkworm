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

#include "header_index.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::snapshots {

Bytes HeaderIndex::KeyFactory::make(ByteView key_data, uint64_t i) {
    auto word = key_data;
    ensure(!word.empty(), [&]() { return "HeaderIndex: word empty i=" + std::to_string(i); });
    const uint8_t first_hash_byte{word[0]};
    const ByteView rlp_encoded_header{word.data() + 1, word.size() - 1};
    const ethash::hash256 hash = keccak256(rlp_encoded_header);
    ensure(hash.bytes[0] == first_hash_byte,
           [&]() { return "HeaderIndex: invalid prefix=" + to_hex(first_hash_byte) + " hash=" + to_hex(hash.bytes); });
    return Bytes{ByteView{hash.bytes}};
}

}  // namespace silkworm::snapshots
