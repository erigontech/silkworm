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

#include "database.hpp"

#include <cassert>

#include "bucket.hpp"
#include "util.hpp"

namespace silkworm::db {
std::optional<BlockHeader> Database::get_header(uint64_t block_number, const evmc::bytes32& block_hash) {
    auto txn{begin_ro_transaction()};
    auto bucket{txn->get_bucket(bucket::kBlockHeaders)};
    Bytes key{block_key(block_number, block_hash)};
    std::optional<ByteView> header_rlp{bucket->get(key)};
    if (!header_rlp) {
        return {};
    }

    BlockHeader header;
    ByteView view{*header_rlp};
    rlp::decode(view, header);
    return header;
}

}  // namespace silkworm::db
