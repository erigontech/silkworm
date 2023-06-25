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

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/db/util.hpp>

namespace silkworm {

// Read all headers up to limit in reverse order from last, processing each one via a user defined callback
// This implementation uses DataModel and is snapshot aware
void for_last_n_headers(const db::DataModel& data_model, size_t n, std::function<void(BlockHeader&&)> callback) {
    auto highest_block_num = data_model.highest_block_number();

    auto first_block_num = highest_block_num > n ? highest_block_num - n + 1 : 0;
    for (auto i = first_block_num; i <= highest_block_num; i++) {
        auto header = data_model.read_header(i);
        if (!header) throw std::logic_error("the headers table must not have any holes");
        callback(std::move(*header));
    }
}

// Return (block-num, hash) of the header with the biggest total difficulty skipping bad headers
// see Erigon's HeadersUnwind method for the implementation
std::tuple<BlockNum, Hash> header_with_biggest_td(db::ROTxn& txn, const std::set<Hash>* bad_headers) {
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

    db::cursor_for_each(*td_cursor, find_max, db::CursorMoveDirection::Reverse);

    return {max_block_num, max_hash};
}

}  // namespace silkworm
