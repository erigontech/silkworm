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
    std::optional<ByteView> hash{header_table->get(db::header_hash_key(block_number))};
    if (!hash) {
        return {};
    }

    BlockWithHash bh{};
    assert(hash->size() == kHashLength);
    std::memcpy(bh.hash.bytes, hash->data(), kHashLength);

    Bytes key{db::block_key(block_number, bh.hash)};
    std::optional<ByteView> header_rlp{header_table->get(key)};
    if (!header_rlp) {
        return {};
    }

    rlp::decode(*header_rlp, bh.block.header);

    auto body_table{txn.open(db::bucket::kBlockBodies)};
    std::optional<ByteView> body_rlp{body_table->get(key)};
    if (!body_rlp) {
        return {};
    }

    rlp::decode<BlockBody>(*body_rlp, bh.block);
    return bh;
}

std::vector<evmc::address> get_senders(lmdb::Transaction& txn, int64_t block_number, const evmc::bytes32& block_hash) {
    std::vector<evmc::address> senders{};
    auto table{txn.open(db::bucket::kSenders)};
    std::optional<ByteView> data{table->get(db::block_key(block_number, block_hash))};
    if (!data) {
        return senders;
    }

    assert(data->length() % kAddressLength == 0);
    senders.resize(data->length() / kAddressLength);
    std::memcpy(senders.data(), data->data(), data->size());
    return senders;
}
}  // namespace silkworm::dal
