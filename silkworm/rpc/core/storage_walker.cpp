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

#include "storage_walker.hpp"

#include <set>
#include <sstream>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/db/util.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/cursor.hpp>
#include <silkworm/rpc/ethdb/transaction_database.hpp>
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"

namespace silkworm::rpc {

silkworm::Bytes make_key(const evmc::address& address, const evmc::bytes32& location) {
    silkworm::Bytes res(silkworm::kAddressLength + silkworm::kHashLength, '\0');
    std::memcpy(&res[0], address.bytes, silkworm::kAddressLength);
    std::memcpy(&res[silkworm::kAddressLength], location.bytes, silkworm::kHashLength);
    return res;
}

silkworm::Bytes make_key(const evmc::address& address, uint64_t incarnation) {
    silkworm::Bytes res(silkworm::kAddressLength + 8, '\0');
    std::memcpy(&res[0], address.bytes, silkworm::kAddressLength);
    endian::store_big_u64(&res[silkworm::kAddressLength], incarnation);
    return res;
}

struct StorageItem {
    silkworm::Bytes key;
    silkworm::Bytes sec_key;
    silkworm::Bytes value;
};

bool operator<(const StorageItem& k1, const StorageItem& k2) {
    return k1.key < k2.key;
}

Task<ethdb::SplittedKeyValue> next(ethdb::SplitCursor& cursor, BlockNum number) {
    auto kv = co_await cursor.next();
    if (kv.key2.empty()) {
        co_return kv;
    }
    BlockNum block = silkworm::endian::load_big_u64(kv.key3.data());
    while (block < number) {
        kv = co_await cursor.next();
        if (kv.key2.empty()) {
            break;
        }
        block = silkworm::endian::load_big_u64(kv.key3.data());
    }
    co_return kv;
}

Task<ethdb::SplittedKeyValue> next(ethdb::SplitCursor& cursor, BlockNum number, BlockNum block, silkworm::Bytes loc) {
    ethdb::SplittedKeyValue skv;
    auto tmp_loc = loc;
    while (!loc.empty() && (tmp_loc == loc || block < number)) {
        skv = co_await cursor.next();
        if (skv.key2.empty()) {
            break;
        }

        loc = skv.key2;
        block = silkworm::endian::load_big_u64(skv.key3.data());
    }
    co_return skv;
}

Task<void> StorageWalker::walk_of_storages(
    BlockNum block_number,
    const evmc::address& address,
    const evmc::bytes32& start_location,
    uint64_t incarnation,
    AccountCollector& collector) {
    SILK_TRACE << "block_number=" << block_number << " address=" << address << " START";

    auto ps_cursor = co_await transaction_.cursor_dup_sort(db::table::kPlainStateName);
    auto ps_key{make_key(address, incarnation)};
    ethdb::SplitCursorDupSort ps_split_cursor{*ps_cursor,
                                              ps_key,
                                              start_location.bytes,     /* subkey */
                                              8 * (kAddressLength + 8), /* match_bits */
                                              kAddressLength,           /* part1_end */
                                              kHashLength};             /* value_offset */

    auto sh_cursor = co_await transaction_.cursor(db::table::kStorageHistoryName);
    auto sh_key{make_key(address, start_location)};
    ethdb::SplitCursor sh_split_cursor{*sh_cursor,
                                       sh_key,
                                       8 * kAddressLength,            /* match_bits */
                                       kAddressLength,                /* part1_end */
                                       kAddressLength,                /* part2_start */
                                       kAddressLength + kHashLength}; /* part3_start */

    auto ps_skv = co_await ps_split_cursor.seek_both();
    auto sh_skv = co_await sh_split_cursor.seek();
    auto h_loc = sh_skv.key2;

    BlockNum block = silkworm::endian::load_big_u64(sh_skv.key3.data());
    auto cs_cursor = co_await transaction_.cursor_dup_sort(db::table::kStorageChangeSetName);

    if (block < block_number) {
        sh_skv = co_await next(sh_split_cursor, block_number);
    }

    auto go_on = true;
    while (go_on) {
        if (ps_skv.key1.empty() && sh_skv.key1.empty()) {
            break;
        }
        auto cmp = ps_skv.key1.compare(sh_skv.key1);
        if (cmp == 0) {
            if (ps_skv.key2.empty() && h_loc.empty()) {
                break;
            }
            cmp = ps_skv.key2.compare(h_loc);
        }
        if (cmp < 0) {
            const auto ps_address = bytes_to_address(ps_skv.key1);
            go_on = collector(ps_address, ps_skv.key2, ps_skv.value);
        } else {
            std::optional<uint64_t> found;

            if (!sh_skv.value.empty()) {
                const auto bitmap = silkworm::db::bitmap::parse(sh_skv.value);
                found = silkworm::db::bitmap::seek(bitmap, block_number);
            }
            if (found) {
                auto dup_key{silkworm::db::storage_change_key(found.value(), address, incarnation)};

                auto data = co_await cs_cursor->seek_both(dup_key, h_loc);
                if (data.length() > silkworm::kHashLength) {  // Skip deleted entries
                    data = data.substr(silkworm::kHashLength);
                    const auto ps_address = bytes_to_address(ps_skv.key1);
                    go_on = collector(ps_address, ps_skv.key2, data);
                }
            } else if (cmp == 0) {
                const auto ps_address = bytes_to_address(ps_skv.key1);
                go_on = collector(ps_address, ps_skv.key2, ps_skv.value);
            }
        }
        if (go_on) {
            if (cmp <= 0) {
                ps_skv = co_await ps_split_cursor.next_dup();
            }
            if (cmp >= 0) {
                const auto sh_block = silkworm::endian::load_big_u64(sh_skv.key3.data());
                sh_skv = co_await next(sh_split_cursor, block_number, sh_block, h_loc);
                h_loc = sh_skv.key2;
            }
        }
    }
    SILK_TRACE << "block_number=" << block_number << " address=" << address << " END";
    co_return;
}

Task<void> StorageWalker::storage_range_at(
    BlockNum block_number,
    const evmc::address& address,
    const evmc::bytes32& start_location,
    size_t max_result,
    StorageCollector& collector) {
    ethdb::TransactionDatabase tx_database{transaction_};
    auto account_data = co_await tx_database.get_one(db::table::kPlainStateName, full_view(address));

    auto account = silkworm::Account::from_encoded_storage(account_data);
    silkworm::success_or_throw(account);

    std::set<StorageItem> storage;
    AccountCollector walker = [&](const evmc::address& addr, const silkworm::ByteView loc, const silkworm::ByteView data) {
        if (addr != address) {
            return false;
        }
        if (data.empty()) {
            return true;
        }

        auto hash = hash_of(loc);

        StorageItem storage_item;
        storage_item.key = loc;
        storage_item.sec_key = full_view(hash);
        storage_item.value = data;

        if (storage.find(storage_item) != storage.end()) {
            return true;
        }

        storage.insert(storage_item);
        return storage.size() <= max_result;
    };

    StorageWalker storage_walker{transaction_};
    co_await storage_walker.walk_of_storages(block_number + 1, address, start_location, account->incarnation, walker);

    for (const auto& item : storage) {
        collector(item.key, item.sec_key, item.value);
    }
    co_return;
}

}  // namespace silkworm::rpc
