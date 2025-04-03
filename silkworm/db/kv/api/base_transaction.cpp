// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "base_transaction.hpp"

#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::db::kv::api {

Task<KeyValue> BaseTransaction::get(const std::string& table, ByteView key) {
    const auto new_cursor = co_await cursor(table);
    SILK_TRACE << "BaseTransaction::get cursor_id: " << new_cursor->cursor_id();
    const auto kv_pair = co_await new_cursor->seek(key);
    SILK_TRACE << "BaseTransaction::get key: " << kv_pair.key << " value: " << kv_pair.value;
    co_return kv_pair;
}

Task<silkworm::Bytes> BaseTransaction::get_one(const std::string& table, ByteView key) {
    const auto new_cursor = co_await cursor(table);
    SILK_TRACE << "BaseTransaction::get_one cursor_id: " << new_cursor->cursor_id();
    const auto kv_pair = co_await new_cursor->seek_exact(key);
    SILK_TRACE << "BaseTransaction::get_one key: " << kv_pair.key << " value: " << kv_pair.value;
    co_return kv_pair.value;
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
    co_return value.substr(subkey.size());
}

}  // namespace silkworm::db::kv::api
