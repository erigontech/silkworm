/*
   Copyright 2024 The Silkworm Authors

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

#include "walk.hpp"

#include <silkworm/db/kv/api/util.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc::ethdb {

Task<void> walk(db::kv::api::Transaction& tx, const std::string& table, ByteView start_key, uint32_t fixed_bits, Walker w) {
    const auto fixed_bytes = (fixed_bits + 7) / CHAR_BIT;
    SILK_TRACE << "rpc::ethdb::walk fixed_bits: " << fixed_bits << " fixed_bytes: " << fixed_bytes;
    const auto shift_bits = fixed_bits & 7;
    uint8_t mask{0xff};
    if (shift_bits != 0) {
        mask = static_cast<uint8_t>(0xff << (CHAR_BIT - shift_bits));
    }
    SILK_TRACE << "mask: " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mask) << std::dec;

    const auto new_cursor = co_await tx.cursor(table);
    SILK_TRACE << "rpc::ethdb::walk cursor_id: " << new_cursor->cursor_id();
    auto kv_pair = co_await new_cursor->seek(start_key);
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
        kv_pair = co_await new_cursor->next();
        k = kv_pair.key;
        v = kv_pair.value;
    }
}

Task<void> for_prefix(db::kv::api::Transaction& tx, const std::string& table, ByteView prefix, Walker w) {
    const auto new_cursor = co_await tx.cursor(table);
    SILK_TRACE << "rpc::ethdb::for_prefix cursor_id: " << new_cursor->cursor_id() << " prefix: " << silkworm::to_hex(prefix);
    auto kv_pair = co_await new_cursor->seek(prefix);
    auto k = kv_pair.key;
    auto v = kv_pair.value;
    SILK_TRACE << "rpc::ethdb::for_prefix k: " << k << " v: " << v;
    while (k.substr(0, prefix.size()) == prefix) {
        const auto go_on = w(k, v);
        if (!go_on) {
            break;
        }
        kv_pair = co_await new_cursor->next();
        k = kv_pair.key;
        v = kv_pair.value;
        SILK_TRACE << "rpc::ethdb::for_prefix k: " << k << " v: " << v;
    }
}

}  // namespace silkworm::rpc::ethdb
