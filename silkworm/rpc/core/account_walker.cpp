/*
   Copyright 2023 The Silkworm Authors

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

#include "account_walker.hpp"

#include <silkworm/core/common/endian.hpp>
#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/db/util.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/cursor.hpp>

namespace silkworm::rpc {

Task<void> AccountWalker::walk_of_accounts(BlockNum block_number, const evmc::address& start_address, Collector& collector) {
    auto ps_cursor = co_await transaction_.cursor(db::table::kPlainStateName);

    auto start_key = full_view(start_address);
    auto ps_kv = co_await seek(*ps_cursor, start_key, kAddressLength);
    if (ps_kv.key.empty()) {
        co_return;
    }

    auto ah_cursor = co_await transaction_.cursor(db::table::kAccountHistoryName);
    ethdb::SplitCursor split_cursor{*ah_cursor, start_key, 0, kAddressLength, kAddressLength, kAddressLength + 8};

    auto s_kv = co_await seek(split_cursor, block_number);

    auto acs_cursor = co_await transaction_.cursor_dup_sort(db::table::kAccountChangeSetName);

    auto go_on = true;
    while (go_on) {
        if (ps_kv.key.empty() && s_kv.key1.empty()) {
            break;
        }
        auto cmp = ps_kv.key.compare(s_kv.key1);
        if (cmp < 0) {
            go_on = collector(ps_kv.key, ps_kv.value);
        } else {
            const auto bitmap = silkworm::db::bitmap::parse(s_kv.value);

            const auto found = silkworm::db::bitmap::seek(bitmap, block_number);
            if (found) {
                const auto block_key{silkworm::db::block_key(found.value())};
                auto data = co_await acs_cursor->seek_both(block_key, s_kv.key1);

                if (data.size() > kAddressLength) {
                    data = data.substr(kAddressLength);
                    go_on = collector(s_kv.key1, data);
                } else {
                }
            } else if (cmp == 0) {
                go_on = collector(ps_kv.key, ps_kv.value);
            }
        }

        if (go_on) {
            if (cmp <= 0) {
                ps_kv = co_await next(*ps_cursor, kAddressLength);
            }
            if (cmp >= 0) {
                auto block = endian::load_big_u64(s_kv.key2.data());
                s_kv = co_await next(split_cursor, block_number, block, s_kv.key1);
            }
        }
    }
}

Task<KeyValue> AccountWalker::next(ethdb::Cursor& cursor, uint64_t len) {
    auto kv = co_await cursor.next();
    while (!kv.key.empty() && kv.key.size() > len) {
        kv = co_await cursor.next();
    }
    co_return kv;
}

Task<KeyValue> AccountWalker::seek(ethdb::Cursor& cursor, silkworm::ByteView key, uint64_t len) {
    auto kv = co_await cursor.seek(key);
    if (kv.key.size() > len) {
        co_return co_await next(cursor, len);
    }
    co_return kv;
}

Task<ethdb::SplittedKeyValue> AccountWalker::next(ethdb::SplitCursor& cursor, BlockNum number, BlockNum block, silkworm::Bytes addr) {
    ethdb::SplittedKeyValue skv;
    auto tmp_addr = addr;
    while (!addr.empty() && (tmp_addr == addr || block < number)) {
        skv = co_await cursor.next();

        if (skv.key1.empty()) {
            break;
        }
        block = silkworm::endian::load_big_u64(skv.key2.data());
        addr = skv.key1;
    }
    co_return skv;
}

Task<ethdb::SplittedKeyValue> AccountWalker::seek(ethdb::SplitCursor& cursor, BlockNum number) {
    auto kv = co_await cursor.seek();
    if (kv.key1.empty()) {
        co_return kv;
    }

    BlockNum block = silkworm::endian::load_big_u64(kv.key2.data());
    while (block < number) {
        kv = co_await cursor.next();
        if (kv.key2.empty()) {
            break;
        }
        block = silkworm::endian::load_big_u64(kv.key2.data());
    }

    co_return kv;
}

}  // namespace silkworm::rpc
