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

#include "db_utils.hpp"

#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::db {

// Return (block-num, hash) of the header with the biggest total difficulty skipping bad headers
// see Erigon's HeadersUnwind method for the implementation
std::tuple<BlockNum, Hash> header_with_biggest_td(datastore::kvdb::ROTxn& txn, const std::set<Hash>* bad_headers) {
    BlockNum max_block_num = 0;
    Hash max_hash;
    intx::uint256 max_td = 0;

    auto td_cursor = txn.ro_cursor(db::table::kDifficulty);

    auto find_max = [bad_headers, &max_block_num, &max_hash, &max_td](ByteView key, ByteView value) {
        SILKWORM_ASSERT(key.size() == sizeof(BlockNum) + kHashLength);

        Hash hash{key.substr(sizeof(BlockNum))};
        ByteView block_num = key.substr(0, sizeof(BlockNum));

        if (bad_headers && bad_headers->contains(hash)) {
            return;
        }

        intx::uint256 td = 0;
        success_or_throw(rlp::decode(value, td));

        if (td > max_td) {
            max_td = td;
            max_hash = hash;
            max_block_num = endian::load_big_u64(block_num.data());
        }

        // TODO: check if we really need to parse all the table
    };

    datastore::kvdb::cursor_for_each(*td_cursor, find_max, datastore::kvdb::CursorMoveDirection::kReverse);

    return {max_block_num, max_hash};
}

}  // namespace silkworm::db
