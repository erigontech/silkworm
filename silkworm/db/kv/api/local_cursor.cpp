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

#include <silkworm/infra/common/clock_time.hpp>
#include <silkworm/infra/common/log.hpp>

#include "../api/util.hpp"

namespace silkworm::db::kv::api {

Task<void> LocalCursor::open_cursor(const std::string& table_name, bool is_dup_sorted) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "LocalCursor::open_cursor opening new cursor for table: " << table_name;
    // table_name name must be a valid MDBX map name
    if (!silkworm::db::has_map(txn_, table_name.c_str())) {
        const auto error_message = "unknown table: " + table_name;
        SILK_ERROR << "open_cursor !has_map: " << table_name << " " << is_dup_sorted << error_message;
        throw std::runtime_error(error_message);
    }
    SILK_DEBUG << "LocalCursor::open_cursor [" << table_name << "] c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return;
}

Task<KeyValue> LocalCursor::seek(ByteView key) {
    SILK_DEBUG << "LocalCursor::seek cursor: " << cursor_id_ << " key: " << key;
    mdbx::slice mdbx_key{key};

    const auto result = (key.empty()) ? db_cursor_.to_first(/*throw_notfound=*/false) : db_cursor_.lower_bound(mdbx_key, /*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::seek result: " << db::detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::seek found: key: " << key << " value: " << byte_view_of_string(result.value.as_string());
        co_return KeyValue{bytes_of_string(result.key.as_string()), bytes_of_string(result.value.as_string())};
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
        SILK_DEBUG << "LocalCursor::seek_exact result: " << db::detail::dump_mdbx_result(result);
        if (result) {
            SILK_DEBUG << "LocalCursor::seek_exact found: "
                       << " key: " << key << " value: " << byte_view_of_string(result.value.as_string());
            co_return KeyValue{bytes_of_string(result.key.as_string()), bytes_of_string(result.value.as_string())};
        }
        SILK_ERROR << "LocalCursor::seek_exact !result key: " << key;
    }
    co_return KeyValue{};
}

Task<KeyValue> LocalCursor::next() {
    SILK_DEBUG << "LocalCursor::next: " << cursor_id_;

    const auto result = db_cursor_.to_next(/*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::next result: " << db::detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::next: "
                   << " key: " << byte_view_of_string(result.key.as_string()) << " value: " << byte_view_of_string(result.value.as_string());
        co_return KeyValue{bytes_of_string(result.key.as_string()), bytes_of_string(result.value.as_string())};
    } else {
        SILK_ERROR << "LocalCursor::next !result";
    }
    co_return KeyValue{};
}

Task<KeyValue> LocalCursor::previous() {
    SILK_DEBUG << "LocalCursor::previous: " << cursor_id_;

    const auto result = db_cursor_.to_previous(/*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::previous result: " << db::detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::previous: "
                   << " key: " << byte_view_of_string(result.key.as_string()) << " value: " << byte_view_of_string(result.value.as_string());
        co_return KeyValue{bytes_of_string(result.key.as_string()), bytes_of_string(result.value.as_string())};
    } else {
        SILK_ERROR << "LocalCursor::previous !result";
    }
    co_return KeyValue{};
}

Task<KeyValue> LocalCursor::next_dup() {
    SILK_DEBUG << "LocalCursor::next_dup: " << cursor_id_;

    const auto result = db_cursor_.to_current_next_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::next_dup result: " << db::detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::next_dup: "
                   << " key: " << byte_view_of_string(result.key.as_string()) << " value: " << byte_view_of_string(result.value.as_string());
        co_return KeyValue{bytes_of_string(result.key.as_string()), bytes_of_string(result.value.as_string())};
    } else {
        SILK_ERROR << "LocalCursor::next_dup !result";
    }
    co_return KeyValue{};
}

Task<Bytes> LocalCursor::seek_both(silkworm::ByteView key, silkworm::ByteView value) {
    SILK_DEBUG << "LocalCursor::seek_both cursor: " << cursor_id_ << " key: " << key << " subkey: " << value;

    const auto result = db_cursor_.lower_bound_multivalue(key, value, /*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::seek_both result: " << db::detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::seek_both key: " << byte_view_of_string(result.key.as_string()) << " value: " << byte_view_of_string(result.value.as_string());
        co_return bytes_of_string(result.value.as_string());
    }
    co_return bytes_of_string("");
}

Task<KeyValue> LocalCursor::seek_both_exact(silkworm::ByteView key, silkworm::ByteView value) {
    SILK_DEBUG << "LocalCursor::seek_both_exact cursor: " << cursor_id_ << " key: " << key << " subkey: " << value;

    const auto result = db_cursor_.find_multivalue(key, value, /*throw_notfound=*/false);
    SILK_DEBUG << "LocalCursor::seek_both_exact result: " << db::detail::dump_mdbx_result(result);

    if (result) {
        SILK_DEBUG << "LocalCursor::seek_both_exact: "
                   << " key: " << byte_view_of_string(result.key.as_string()) << " value: " << byte_view_of_string(result.value.as_string());
        co_return KeyValue{bytes_of_string(result.key.as_string()), bytes_of_string(result.value.as_string())};
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
