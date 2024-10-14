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

#include "local_cursor.hpp"

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/datastore/mdbx/mdbx.hpp>
#include <silkworm/infra/common/clock_time.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::db::kv::api {

using detail::slice_as_hex;

Task<void> LocalCursor::open_cursor(const std::string& table_name, bool is_dup_sorted) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "LocalCursor::open_cursor opening new cursor for table: " << table_name;
    db_cursor_ = PooledCursor{txn_,
                              MapConfig{
                                  .name = table_name.c_str(),
                                  .value_mode = is_dup_sorted ? ::mdbx::value_mode::multi : ::mdbx::value_mode::single}};
    SILK_DEBUG << "LocalCursor::open_cursor [" << table_name << "] c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return;
}

Task<KeyValue> LocalCursor::seek(ByteView key) {
    SILK_DEBUG << "LocalCursor::seek cursor: " << cursor_id_ << " key: " << key;
    mdbx::slice mdbx_key{key};

    const auto result = (key.empty()) ? db_cursor_.to_first(/*throw_notfound=*/false) : db_cursor_.lower_bound(mdbx_key, /*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::seek result: " << detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::seek found: key: " << key << " value: " << slice_as_hex(result.value);
        co_return KeyValue{string_to_bytes(result.key.as_string()), string_to_bytes(result.value.as_string())};
    } else {
        SILK_DEBUG << "LocalCursor::seek not found key: " << key;
        co_return KeyValue{};
    }
}

Task<KeyValue> LocalCursor::seek_exact(ByteView key) {
    SILK_DEBUG << "LocalCursor::seek_exact cursor: " << cursor_id_ << " key: " << key;

    const bool found = db_cursor_.seek(key);
    if (found) {
        const auto result = db_cursor_.current(/*throw_notfound=*/false);
        SILK_DEBUG << "LocalCursor::seek_exact result: " << detail::dump_mdbx_result(result);
        if (result) {
            SILK_DEBUG << "LocalCursor::seek_exact found: key: " << key << " value: " << slice_as_hex(result.value);
            co_return KeyValue{string_to_bytes(result.key.as_string()), string_to_bytes(result.value.as_string())};
        }
        SILK_ERROR << "LocalCursor::seek_exact !result key: " << key;  // TODO(canepat) handle properly?
    }
    co_return KeyValue{};
}

Task<KeyValue> LocalCursor::first() {
    SILK_DEBUG << "LocalCursor::first: " << cursor_id_;

    const auto result = db_cursor_.to_first(/*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::first result: " << detail::dump_mdbx_result(result);
    if (!result.done) {
        co_return KeyValue{};
    }

    SILK_DEBUG << "LocalCursor::first: key: " << slice_as_hex(result.key) << " value: " << slice_as_hex(result.value);
    co_return KeyValue{string_to_bytes(result.key.as_string()), string_to_bytes(result.value.as_string())};
}

Task<KeyValue> LocalCursor::last() {
    SILK_DEBUG << "LocalCursor::last: " << cursor_id_;

    const auto result = db_cursor_.to_last(/*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::last result: " << detail::dump_mdbx_result(result);
    if (!result.done) {
        co_return KeyValue{};
    }

    SILK_DEBUG << "LocalCursor::last: key: " << slice_as_hex(result.key) << " value: " << slice_as_hex(result.value);
    co_return KeyValue{string_to_bytes(result.key.as_string()), string_to_bytes(result.value.as_string())};
}

Task<KeyValue> LocalCursor::next() {
    SILK_DEBUG << "LocalCursor::next: " << cursor_id_;

    const auto result = db_cursor_.to_next(/*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::next result: " << detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::next: "
                   << " key: " << string_view_to_byte_view(result.key.as_string()) << " value: " << string_view_to_byte_view(result.value.as_string());
        co_return KeyValue{string_to_bytes(result.key.as_string()), string_to_bytes(result.value.as_string())};
    } else {
        SILK_ERROR << "LocalCursor::next !result";  // TODO(canepat) handle properly?
    }
    co_return KeyValue{};
}

Task<KeyValue> LocalCursor::previous() {
    SILK_DEBUG << "LocalCursor::previous: " << cursor_id_;

    const auto result = db_cursor_.to_previous(/*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::previous result: " << detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::previous: "
                   << " key: " << string_view_to_byte_view(result.key.as_string()) << " value: " << string_view_to_byte_view(result.value.as_string());
        co_return KeyValue{string_to_bytes(result.key.as_string()), string_to_bytes(result.value.as_string())};
    } else {
        SILK_ERROR << "LocalCursor::previous !result";  // TODO(canepat) handle properly?
    }
    co_return KeyValue{};
}

Task<KeyValue> LocalCursor::next_dup() {
    SILK_DEBUG << "LocalCursor::next_dup: " << cursor_id_;

    const auto result = db_cursor_.to_current_next_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::next_dup result: " << detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::next_dup: "
                   << " key: " << string_view_to_byte_view(result.key.as_string()) << " value: " << string_view_to_byte_view(result.value.as_string());
        co_return KeyValue{string_to_bytes(result.key.as_string()), string_to_bytes(result.value.as_string())};
    } else {
        SILK_ERROR << "LocalCursor::next_dup !result";  // TODO(canepat) handle properly?
    }
    co_return KeyValue{};
}

Task<Bytes> LocalCursor::seek_both(ByteView key, ByteView value) {
    SILK_DEBUG << "LocalCursor::seek_both cursor: " << cursor_id_ << " key: " << key << " subkey: " << value;

    const auto result = db_cursor_.lower_bound_multivalue(key, value, /*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::seek_both result: " << detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::seek_both key: " << string_view_to_byte_view(result.key.as_string()) << " value: " << string_view_to_byte_view(result.value.as_string());
        co_return string_to_bytes(result.value.as_string());
    }
    co_return string_to_bytes("");
}

Task<KeyValue> LocalCursor::seek_both_exact(ByteView key, ByteView value) {
    SILK_DEBUG << "LocalCursor::seek_both_exact cursor: " << cursor_id_ << " key: " << key << " subkey: " << value;

    const auto result = db_cursor_.find_multivalue(key, value, /*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::seek_both_exact result: " << detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::seek_both_exact: "
                   << " key: " << string_view_to_byte_view(result.key.as_string()) << " value: " << string_view_to_byte_view(result.value.as_string());
        co_return KeyValue{string_to_bytes(result.key.as_string()), string_to_bytes(result.value.as_string())};
    } else {
        SILK_ERROR << "LocalCursor::seek_both_exact !found key: " << key << " subkey:" << value;
    }
    co_return KeyValue{};
}

Task<void> LocalCursor::close_cursor() {
    SILK_DEBUG << "LocalCursor::close_cursor c=" << cursor_id_;
    cursor_id_ = 0;
    co_return;
}

}  // namespace silkworm::db::kv::api
