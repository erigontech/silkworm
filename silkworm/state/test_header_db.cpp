/*
   Copyright 2020 The Silkworm Authors

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

#include "test_header_db.hpp"

#include <cstring>
#include <ethash/keccak.hpp>
#include <utility>

namespace silkworm {

std::optional<BlockHeader> TestHeaderDB::read_header(uint64_t, const evmc::bytes32& block_hash) const noexcept {
    auto it{headers_.find(block_hash)};
    if (it == headers_.end()) {
        return {};
    } else {
        return it->second;
    }
}

void TestHeaderDB::write_header(BlockHeader block_header) {
    Bytes rlp{};
    rlp::encode(rlp, block_header);
    ethash::hash256 hash{ethash::keccak256(rlp.data(), rlp.size())};
    evmc::bytes32 key;
    std::memcpy(key.bytes, hash.bytes, kHashLength);
    headers_[key] = std::move(block_header);
}

}  // namespace silkworm
