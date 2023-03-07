/*
    Copyright 2020 The Silkrpc Authors

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

#include <silkworm/silkrpc/common/clock_time.hpp>
#include <silkworm/node/backend/rpc/kv_calls.hpp>

namespace silkrpc::ethdb::file {

boost::asio::awaitable<void> LocalCursor::open_cursor(const std::string& table_name, bool is_dup_sorted) {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "LocalCursor::open_cursor opening new cursor for table: " << table_name << "\n";
    // table_name name must be a valid MDBX map name
    if (!silkworm::db::has_map(read_only_txn_, table_name.c_str())) {
        const auto error_message = "unknown table: " + table_name;
        SILKRPC_ERROR << "open_cursor !has_map: " << table_name << " " << is_dup_sorted <<  error_message;
        throw std::runtime_error(error_message);
    }
    SILKRPC_DEBUG << "LocalCursor::open_cursor [" << table_name << "] c=" << cursor_id_ << " t=" << clock_time::since(start_time) << "\n";
    co_return;
}

boost::asio::awaitable<KeyValue> LocalCursor::seek(silkworm::ByteView key) {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "LocalCursor::seek cursor: " << cursor_id_ << " key: " << key << "\n";
    mdbx::slice mdbx_key{key};

    const auto result = (key.length() == 0) ? db_cursor_.to_first(/*throw_notfound=*/false) : db_cursor_.lower_bound(mdbx_key, /*throw_notfound=*/false);
    SILKRPC_DEBUG << "LocalCursor::seek result: " << silkworm::rpc::detail::dump_mdbx_result(result) << "\n";

    if (result) {
        SILKRPC_DEBUG << "LocalCursor::seek found: " << " key: " << key << " value: " << silkworm::bytes_of_string(result.value.as_string()) << "\n";
        co_return KeyValue{silkworm::bytes_of_string(result.key.as_string()), silkworm::bytes_of_string(result.value.as_string())};
    } else {
        SILKRPC_ERROR << "LocalCursor::seek !result key: " << key << "\n";
    }
    co_return KeyValue{};
}

boost::asio::awaitable<KeyValue> LocalCursor::seek_exact(silkworm::ByteView key) {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "LocalCursor::seek_exact cursor: " << cursor_id_ << " key: " << key << "\n";

    const bool found = db_cursor_.seek(key);
    if (found) {
        const auto result = db_cursor_.current(/*throw_notfound=*/false);
        SILKRPC_DEBUG << "LocalCursor::seek_exact result: " << silkworm::rpc::detail::dump_mdbx_result(result) << "\n";
        if (result) {
            SILKRPC_DEBUG << "LocalCursor::seek_exact found: " << " key: " << key << " value: " << silkworm::bytes_of_string(result.value.as_string()) << "\n";
            co_return KeyValue{silkworm::bytes_of_string(result.key.as_string()), silkworm::bytes_of_string(result.value.as_string())};
        }
        SILKRPC_ERROR << "LocalCursor::seek_exact !result key: " << key << "\n";
    }
    co_return KeyValue{};
}

boost::asio::awaitable<KeyValue> LocalCursor::next() {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "LocalCursor::next: " << cursor_id_ << "\n";

    const auto result = db_cursor_.to_next(/*throw_notfound=*/false);
    SILKRPC_DEBUG << "LocalCursor::next result: " << silkworm::rpc::detail::dump_mdbx_result(result) << "\n";

    if (result) {
        SILKRPC_DEBUG << "LocalCursor::next: " << " key: " << silkworm::bytes_of_string(result.key.as_string()) << " value: " << silkworm::bytes_of_string(result.value.as_string()) << "\n";
        co_return KeyValue{silkworm::bytes_of_string(result.key.as_string()), silkworm::bytes_of_string(result.value.as_string())};
    } else {
        SILKRPC_ERROR << "LocalCursor::next !result" << "\n";
    }
    co_return KeyValue{};
}

boost::asio::awaitable<KeyValue> LocalCursor::next_dup() {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "LocalCursor::next_dup: " << cursor_id_ << "\n";

    const auto result = db_cursor_.to_current_next_multi(/*throw_notfound=*/false);
    SILKRPC_DEBUG << "LocalCursor::next_dup result: " << silkworm::rpc::detail::dump_mdbx_result(result) << "\n";

    if (result) {
        SILKRPC_DEBUG << "LocalCursor::next_dup: " << " key: " << silkworm::bytes_of_string(result.key.as_string()) <<
                         " value: " << silkworm::bytes_of_string(result.value.as_string()) << "\n";
        co_return KeyValue{silkworm::bytes_of_string(result.key.as_string()), silkworm::bytes_of_string(result.value.as_string())};
    } else {
        SILKRPC_ERROR << "LocalCursor::next_dup !result" << "\n";
    }
    co_return KeyValue{};
}

boost::asio::awaitable<silkworm::Bytes> LocalCursor::seek_both(silkworm::ByteView key, silkworm::ByteView value) {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "LocalCursor::seek_both cursor: " << cursor_id_ << " key: " << key << " subkey: " << value << "\n";
    mdbx::slice mdbx_key{key};
    mdbx::slice mdbx_value{value};

    const auto result = db_cursor_.lower_bound_multivalue(mdbx_key, mdbx_value, /*throw_notfound=*/false);
    SILKRPC_DEBUG << "LocalCursor::seek_both result: " << silkworm::rpc::detail::dump_mdbx_result(result) << "\n";

    if (result) {
        SILKRPC_DEBUG << "LocalCursor::seek_both key: " << silkworm::bytes_of_string(result.key.as_string()) <<
                         " value: " << silkworm::bytes_of_string(result.value.as_string()) << "\n";
        co_return silkworm::bytes_of_string(result.value.as_string());
    }
    co_return silkworm::bytes_of_string("");
}

boost::asio::awaitable<KeyValue> LocalCursor::seek_both_exact(silkworm::ByteView key, silkworm::ByteView value) {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "LocalCursor::seek_both_exact cursor: " << cursor_id_ << " key: " << key << " subkey: " << value << "\n";
    mdbx::slice mdbx_key{key};
    mdbx::slice mdbx_value{value};

    const auto result = db_cursor_.find_multivalue(key, value, /*throw_notfound=*/false);
    SILKRPC_DEBUG << "LocalCursor::seek_both_exact result: " << silkworm::rpc::detail::dump_mdbx_result(result) << "\n";

    if (result) {
        SILKRPC_DEBUG << "LocalCursor::seek_both_exact: " << " key: " << silkworm::bytes_of_string(result.key.as_string()) <<
                                                             " value: " << silkworm::bytes_of_string(result.value.as_string()) << "\n";
        co_return KeyValue{silkworm::bytes_of_string(result.key.as_string()), silkworm::bytes_of_string(result.value.as_string())};
    } else {
        SILKRPC_ERROR << "LocalCursor::seek_both_exact !found key: " << key << " subkey:" << value << "\n";
    }
    co_return KeyValue{};
}

boost::asio::awaitable<void> LocalCursor::close_cursor() {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "LocalCursor::close_cursor c=" << cursor_id_ << " t=" << clock_time::since(start_time) << "\n";
    cursor_id_ = 0;
    co_return;
}

} // namespace silkrpc::ethdb::file
