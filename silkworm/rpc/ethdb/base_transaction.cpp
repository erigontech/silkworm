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

#include "base_transaction.hpp"

#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc::ethdb {

void BaseTransaction::set_state_cache_enabled(bool cache_enabled) {
    get_one_impl_ = cache_enabled ? get_one_impl_with_cache_ : get_one_impl_no_cache_;
}

Task<KeyValue> BaseTransaction::get(const std::string& table, ByteView key) {
    const auto new_cursor = co_await cursor(table);
    SILK_TRACE << "BaseTransaction::get cursor_id: " << new_cursor->cursor_id();
    const auto kv_pair = co_await new_cursor->seek(key);
    SILK_TRACE << "BaseTransaction::get key: " << kv_pair.key << " value: " << kv_pair.value;
    co_return kv_pair;
}

Task<silkworm::Bytes> BaseTransaction::get_one(const std::string& table, ByteView key) {
    co_return co_await std::invoke(get_one_impl_, *this, table, key);
}

Task<std::optional<Bytes>> BaseTransaction::get_both_range(const std::string& table, ByteView key, ByteView subkey) {
    const auto new_cursor = co_await cursor_dup_sort(table);
    SILK_TRACE << "BaseTransaction::get_both_range cursor_id: " << new_cursor->cursor_id();
    const auto value{co_await new_cursor->seek_both(key, subkey)};
    SILK_DEBUG << "BaseTransaction::get_both_range value: " << value << " subkey: " << subkey;
    if (value.substr(0, subkey.size()) != subkey) {
        SILK_DEBUG << "BaseTransaction::get_both_range value: " << value << " subkey: " << subkey;
        co_return std::nullopt;
    }
    co_return value.substr(subkey.length());
}

Task<void> BaseTransaction::walk(const std::string& table, ByteView start_key, uint32_t fixed_bits, Walker w) {
    const auto fixed_bytes = (fixed_bits + 7) / CHAR_BIT;
    SILK_TRACE << "BaseTransaction::walk fixed_bits: " << fixed_bits << " fixed_bytes: " << fixed_bytes;
    const auto shift_bits = fixed_bits & 7;
    uint8_t mask{0xff};
    if (shift_bits != 0) {
        mask = static_cast<uint8_t>(0xff << (CHAR_BIT - shift_bits));
    }
    SILK_TRACE << "mask: " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mask) << std::dec;

    const auto new_cursor = co_await cursor(table);
    SILK_TRACE << "BaseTransaction::walk cursor_id: " << new_cursor->cursor_id();
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

Task<void> BaseTransaction::for_prefix(const std::string& table, ByteView prefix, Walker w) {
    const auto new_cursor = co_await cursor(table);
    SILK_TRACE << "BaseTransaction::for_prefix cursor_id: " << new_cursor->cursor_id() << " prefix: " << silkworm::to_hex(prefix);
    auto kv_pair = co_await new_cursor->seek(prefix);
    auto k = kv_pair.key;
    auto v = kv_pair.value;
    SILK_TRACE << "BaseTransaction::for_prefix k: " << k << " v: " << v;
    while (k.substr(0, prefix.size()) == prefix) {
        const auto go_on = w(k, v);
        if (!go_on) {
            break;
        }
        kv_pair = co_await new_cursor->next();
        k = kv_pair.key;
        v = kv_pair.value;
        SILK_TRACE << "BaseTransaction::for_prefix k: " << k << " v: " << v;
    }
    co_return;
}

Task<silkworm::Bytes> BaseTransaction::get_one_impl_with_cache(const std::string& table, ByteView key) {
    if (state_cache_) {
        // Just PlainState and Code tables are present in state cache
        if (table == db::table::kPlainStateName) {
            std::shared_ptr<kv::StateView> view = state_cache_->get_view(*this);
            if (view != nullptr) {
                // TODO(canepat) remove key copy changing DatabaseReader interface
                const auto value = co_await view->get(silkworm::Bytes{key.data(), key.size()});
                co_return value ? *value : silkworm::Bytes{};
            }
        } else if (table == db::table::kCodeName) {
            std::shared_ptr<kv::StateView> view = state_cache_->get_view(*this);
            if (view != nullptr) {
                // TODO(canepat) remove key copy changing DatabaseReader interface
                const auto value = co_await view->get_code(silkworm::Bytes{key.data(), key.size()});
                co_return value ? *value : silkworm::Bytes{};
            }
        }
    }

    co_return co_await get_one_impl_no_cache(table, key);
}

Task<silkworm::Bytes> BaseTransaction::get_one_impl_no_cache(const std::string& table, ByteView key) {
    const auto new_cursor = co_await cursor(table);
    SILK_TRACE << "BaseTransaction::get_one cursor_id: " << new_cursor->cursor_id();
    const auto kv_pair = co_await new_cursor->seek_exact(key);
    SILK_TRACE << "BaseTransaction::get_one key: " << kv_pair.key << " value: " << kv_pair.value;
    co_return kv_pair.value;
}

}  // namespace silkworm::rpc::ethdb
