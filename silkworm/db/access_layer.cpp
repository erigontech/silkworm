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

#include "access_layer.hpp"

#include <cassert>

#include "bucket.hpp"
#include "lmdb.hpp"
#include "util.hpp"

namespace silkworm::dal {

std::optional<BlockWithHash> get_block(lmdb::Transaction& txn, uint64_t block_number) {
    auto header_table{txn.open(db::bucket::kBlockHeaders)};
    Bytes hash_key_bytes{db::header_hash_key(block_number)};
    MDB_val hash_key_val{db::to_mdb_val(hash_key_bytes)};
    MDB_val hash_val;
    int res{header_table->seek_exact(&hash_key_val, &hash_val)};
    if (res != MDB_SUCCESS) {
        assert(res == MDB_NOTFOUND);
        return {};
    }

    BlockWithHash bh{};
    assert(hash_val.mv_size == kHashLength);
    std::memcpy(bh.hash.bytes, hash_val.mv_data, kHashLength);

    Bytes key_bytes{db::block_key(block_number, bh.hash)};
    MDB_val key_val{db::to_mdb_val(key_bytes)};
    MDB_val header_rlp;
    res = header_table->seek_exact(&key_val, &header_rlp);
    if (res != MDB_SUCCESS) {
        assert(res == MDB_NOTFOUND);
        return {};
    }

    ByteView header_view{db::from_mdb_val(header_rlp)};
    rlp::decode(header_view, bh.block.header);

    auto body_table{txn.open(db::bucket::kBlockBodies)};
    MDB_val body_rlp;
    res = body_table->seek_exact(&key_val, &body_rlp);
    if (res != MDB_SUCCESS) {
        assert(res == MDB_NOTFOUND);
        return {};
    }

    ByteView body_view{db::from_mdb_val(body_rlp)};
    rlp::decode<BlockBody>(body_view, bh.block);

    return bh;
}
}  // namespace silkworm::dal
