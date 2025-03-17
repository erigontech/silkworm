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

namespace silkworm::db::kv::api {

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

Task<Bytes> BaseTransaction::get_one_impl_with_cache(const std::string& table, ByteView key) {
    if (state_cache_) {
        // Just PlainState and Code tables are present in state cache
        if (table == db::table::kPlainStateName) {
            std::shared_ptr<StateView> view = co_await state_cache_->get_view(*this);
            if (view != nullptr) {
                const auto value = co_await view->get(key);
                co_return value ? *value : silkworm::Bytes{};
            }
        } else if (table == db::table::kCodeName) {
            std::shared_ptr<StateView> view = co_await state_cache_->get_view(*this);
            if (view != nullptr) {
                const auto value = co_await view->get_code(key);
                co_return value ? *value : silkworm::Bytes{};
            }
        }
    }

    co_return co_await get_one_impl_no_cache(table, key);
}

Task<Bytes> BaseTransaction::get_one_impl_no_cache(const std::string& table, ByteView key) {
    const auto new_cursor = co_await cursor(table);
    SILK_TRACE << "BaseTransaction::get_one cursor_id: " << new_cursor->cursor_id();
    const auto kv_pair = co_await new_cursor->seek_exact(key);
    SILK_TRACE << "BaseTransaction::get_one key: " << kv_pair.key << " value: " << kv_pair.value;
    co_return kv_pair.value;
}

}  // namespace silkworm::db::kv::api
