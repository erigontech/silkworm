/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_DBTX_HPP
#define SILKWORM_DBTX_HPP

#include <silkworm/common/endian.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>

#include "Types.hpp"

using namespace silkworm;

class DbTx {
    mdbx::env_managed env;
    mdbx::txn_managed txn;

  public:
    explicit DbTx(std::string db_path) {
        db::EnvConfig db_config{db_path};
        db_config.readonly = true;
        env = db::open_env(db_config);
        txn = env.start_read();
    }

    std::optional<Hash> read_canonical_hash(BlockNum b) {  // throws db exceptions // todo: add to db::access_layer.hpp?
        auto hashes_table = db::open_cursor(txn, db::table::kCanonicalHashes);
        // accessing this table with only b we will get the hash of the canonical block at height b
        auto data = hashes_table.find(db::to_slice(db::block_key(b)), /*throw_notfound*/ false);
        if (!data) return std::nullopt;  // not found
        assert(data.value.length() == kHashLength);
        return Hash(db::from_slice(data.value));  // copy
    }

    static Bytes head_header_key() {  // todo: add to db::util.h?
        std::string table_name = db::table::kHeadHeader.name;
        Bytes key{table_name.begin(), table_name.end()};
        return key;
    }

    std::optional<Hash> read_head_header_hash() {  // todo: add to db::access_layer.hpp?
        auto head_header_table = db::open_cursor(txn, db::table::kHeadHeader);
        auto data = head_header_table.find(db::to_slice(head_header_key()), /*throw_notfound*/ false);
        if (!data) return std::nullopt;
        assert(data.value.length() == kHashLength);
        return Hash(db::from_slice(data.value));
    }

    std::optional<BlockHeader> read_header(BlockNum b, Hash h) { return db::read_header(txn, b, h.bytes); }

    std::optional<BlockHeader> read_canonical_header(BlockNum b) {  // also known as read-header-by-number
        std::optional<Hash> h = read_canonical_hash(b);
        if (!h) {
            return std::nullopt;  // not found
        }
        return read_header(b, *h);
    }

    std::optional<ByteView> read_rlp_encoded_header(BlockNum b, Hash h) {
        auto header_table = db::open_cursor(txn, db::table::kHeaders);
        auto key = db::block_key(b, h.bytes);
        auto data = header_table.find(db::to_slice(key), /*throw_notfound*/ false);
        if (!data) return std::nullopt;
        return db::from_slice(data.value);
    }

    static Bytes header_numbers_key(Hash h) {  // todo: add to db::util.h?
        return {h.bytes, 32};
    }

    std::optional<BlockNum> read_block_num(Hash h) {  // todo: add to db::access_layer.hpp?
        auto blockhashes_table = db::open_cursor(txn, db::table::kHeaderNumbers);
        auto key = header_numbers_key(h);
        auto data = blockhashes_table.find(db::to_slice(key), /*throw_notfound*/ false);
        if (!data) {
            return std::nullopt;
        }
        auto block_num = endian::load_big_u64(static_cast<const unsigned char*>(data.value.data()));
        return block_num;
    }

    std::optional<BlockHeader> read_header(Hash h) {  // todo: add to db::access_layer.hpp?
        auto block_num = read_block_num(h);
        if (!block_num) {
            return std::nullopt;
        }
        return read_header(*block_num, h);
    }

    std::optional<BlockBody> read_body(Hash h) {  // todo: add to db::access_layer.hpp?
        auto block_num = read_block_num(h);
        if (!block_num) {
            return std::nullopt;
        }
        bool read_senders = false;
        return db::read_body(txn, *block_num, h.bytes, read_senders);
    }

    std::optional<intx::uint256> read_total_difficulty(BlockNum b, Hash h) {
        return db::read_total_difficulty(txn, b, h.bytes);
    }

    BlockNum stage_progress(const char* stage_name) { return db::stages::get_stage_progress(txn, stage_name); }
};

#endif  // SILKWORM_DBTX_HPP
