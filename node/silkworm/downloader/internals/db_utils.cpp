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

namespace silkworm {

// Read all headers up to limit, in reverse order from last, processing each via a user defined callback
// alternative implementation: use cursor_for_count(cursor, WalkFuncRef, size_t max_count, CursorMoveDirection)
void read_headers_in_reverse_order(mdbx::txn& txn, size_t limit, std::function<void(BlockHeader&&)> callback) {
    db::Cursor header_table(txn, db::table::kHeaders);

    bool throw_notfound = false;
    size_t read = 0;
    auto data = header_table.to_last(throw_notfound);
    while (data && read < limit) {
        // read header
        BlockHeader header;
        ByteView data_view = db::from_slice(data.value);
        rlp::success_or_throw(rlp::decode(data_view, header));
        read++;
        // consume header
        callback(std::move(header));
        // move backward
        data = header_table.to_previous(throw_notfound);
    }
}  // note: maybe we can simplify/replace the implementation with db::cursor_for_count plus lambda

// Return (block-num, hash) of the header with the biggest total difficulty skipping bad headers
// see Erigon's HeadersUnwind method for the implementation
std::tuple<BlockNum, Hash> header_with_biggest_td(mdbx::txn& txn, const std::set<Hash>* bad_headers) {
    BlockNum max_block_num = 0;
    Hash max_hash;
    BigInt max_td = 0;

    auto td_cursor = db::open_cursor(txn, db::table::kDifficulty);

    auto find_max = [bad_headers, &max_block_num, &max_hash, &max_td](ByteView key, ByteView value) {
        SILKWORM_ASSERT(key.size() == sizeof(BlockNum) + kHashLength);

        Hash hash{key.substr(sizeof(BlockNum))};
        ByteView block_num = key.substr(0, sizeof(BlockNum));

        if (bad_headers && bad_headers->contains(hash)) {
            return;
        }

        BigInt td = 0;
        rlp::success_or_throw(rlp::decode(value, td));

        if (td > max_td) {
            max_td = td;
            max_hash = hash;
            max_block_num = endian::load_big_u64(block_num.data());
        }

        // TODO: check if we really need to parse all the table
    };

    db::cursor_for_each(td_cursor, find_max, db::CursorMoveDirection::Reverse);

    return {max_block_num, max_hash};
}

}  // namespace silkworm
