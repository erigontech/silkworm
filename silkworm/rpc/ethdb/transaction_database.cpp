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

#include "transaction_database.hpp"

#include <climits>
#include <exception>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::ethdb {

Task<KeyValue> TransactionDatabase::get(const std::string& table, ByteView key) const {
    const auto cursor = co_await tx_.cursor(table);
    SILK_TRACE << "TransactionDatabase::get cursor_id: " << cursor->cursor_id();
    const auto kv_pair = co_await cursor->seek(key);
    co_return kv_pair;
}

Task<silkworm::Bytes> TransactionDatabase::get_one(const std::string& table, ByteView key) const {
    const auto cursor = co_await tx_.cursor(table);
    SILK_TRACE << "TransactionDatabase::get_one cursor_id: " << cursor->cursor_id();
    const auto kv_pair = co_await cursor->seek_exact(key);
    co_return kv_pair.value;
}

Task<std::optional<Bytes>> TransactionDatabase::get_both_range(const std::string& table, ByteView key, ByteView subkey) const {
    const auto cursor = co_await tx_.cursor_dup_sort(table);
    SILK_TRACE << "TransactionDatabase::get_both_range cursor_id: " << cursor->cursor_id();
    const auto value{co_await cursor->seek_both(key, subkey)};
    SILK_DEBUG << "TransactionDatabase::get_both_range value: " << value << " subkey: " << subkey;
    if (value.substr(0, subkey.size()) != subkey) {
        SILK_DEBUG << "TransactionDatabase::get_both_range value: " << value << " subkey: " << subkey;
        co_return std::nullopt;
    }
    co_return value.substr(subkey.length());
}

Task<void> TransactionDatabase::walk(const std::string& table, ByteView start_key, uint32_t fixed_bits, core::rawdb::Walker w) const {
    const auto fixed_bytes = (fixed_bits + 7) / CHAR_BIT;
    SILK_TRACE << "TransactionDatabase::walk fixed_bits: " << fixed_bits << " fixed_bytes: " << fixed_bytes;
    const auto shift_bits = fixed_bits & 7;
    uint8_t mask{0xff};
    if (shift_bits != 0) {
        mask = static_cast<uint8_t>(0xff << (CHAR_BIT - shift_bits));
    }
    SILK_TRACE << "mask: " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mask) << std::dec;

    const auto cursor = co_await tx_.cursor(table);
    SILK_TRACE << "TransactionDatabase::walk cursor_id: " << cursor->cursor_id();
    auto kv_pair = co_await cursor->seek(start_key);
    auto k = kv_pair.key;
    auto v = kv_pair.value;
    SILK_TRACE << "k: " << k << " v: " << v;
    while (
        !k.empty() &&
        k.size() >= fixed_bytes &&
        (fixed_bits == 0 || (k.compare(0, fixed_bytes - 1, start_key, 0, fixed_bytes - 1) == 0 && (k[fixed_bytes - 1] & mask) == (start_key[fixed_bytes - 1] & mask)))) {
        const auto go_on = w(k, v);
        if (!go_on) {
            break;
        }
        kv_pair = co_await cursor->next();
        k = kv_pair.key;
        v = kv_pair.value;
    }

    co_return;
}

Task<void> TransactionDatabase::for_prefix(const std::string& table, ByteView prefix, core::rawdb::Walker w) const {
    const auto cursor = co_await tx_.cursor(table);
    SILK_TRACE << "TransactionDatabase::for_prefix cursor_id: " << cursor->cursor_id() << " prefix: " << silkworm::to_hex(prefix);
    auto kv_pair = co_await cursor->seek(prefix);
    auto k = kv_pair.key;
    auto v = kv_pair.value;
    SILK_TRACE << "TransactionDatabase::for_prefix k: " << k << " v: " << v;
    while (k.substr(0, prefix.size()) == prefix) {
        const auto go_on = w(k, v);
        if (!go_on) {
            break;
        }
        kv_pair = co_await cursor->next();
        k = kv_pair.key;
        v = kv_pair.value;
        SILK_TRACE << "TransactionDatabase::for_prefix k: " << k << " v: " << v;
    }
    co_return;
}

}  // namespace silkworm::rpc::ethdb
