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

#include "remote_cursor.hpp"

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/clock_time.hpp>

namespace silkworm::rpc::ethdb::kv {

Task<void> RemoteCursor::open_cursor(const std::string& table_name, bool is_dup_sorted) {
    const auto start_time = clock_time::now();
    if (cursor_id_ == 0) {
        SILK_DEBUG << "RemoteCursor::open_cursor opening new cursor for table: " << table_name;
        auto open_message = remote::Cursor{};
        if (is_dup_sorted) {
            open_message.set_op(remote::Op::OPEN_DUP_SORT);
        } else {
            open_message.set_op(remote::Op::OPEN);
        }
        open_message.set_bucket_name(table_name);
        cursor_id_ = (co_await tx_rpc_.write_and_read(open_message)).cursor_id();
        SILK_DEBUG << "RemoteCursor::open_cursor cursor: " << cursor_id_ << " for table: " << table_name;
    }
    SILK_DEBUG << "RemoteCursor::open_cursor [" << table_name << "] c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return;
}

Task<KeyValue> RemoteCursor::seek(silkworm::ByteView key) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "RemoteCursor::seek cursor: " << cursor_id_ << " key: " << key;
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK);
    seek_message.set_cursor(cursor_id_);
    seek_message.set_k(key.data(), key.length());
    auto seek_pair = co_await tx_rpc_.write_and_read(seek_message);
    const auto k = silkworm::bytes_of_string(seek_pair.k());
    const auto v = silkworm::bytes_of_string(seek_pair.v());
    SILK_DEBUG << "RemoteCursor::seek k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return KeyValue{k, v};
}

Task<KeyValue> RemoteCursor::seek_exact(silkworm::ByteView key) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "RemoteCursor::seek_exact cursor: " << cursor_id_ << " key: " << key;
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK_EXACT);
    seek_message.set_cursor(cursor_id_);
    seek_message.set_k(key.data(), key.length());
    auto seek_pair = co_await tx_rpc_.write_and_read(seek_message);
    const auto k = silkworm::bytes_of_string(seek_pair.k());
    const auto v = silkworm::bytes_of_string(seek_pair.v());
    SILK_DEBUG << "RemoteCursor::seek_exact k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return KeyValue{k, v};
}

Task<KeyValue> RemoteCursor::next() {
    const auto start_time = clock_time::now();
    auto next_message = remote::Cursor{};
    next_message.set_op(remote::Op::NEXT);
    next_message.set_cursor(cursor_id_);
    auto next_pair = co_await tx_rpc_.write_and_read(next_message);
    const auto k = silkworm::bytes_of_string(next_pair.k());
    const auto v = silkworm::bytes_of_string(next_pair.v());
    SILK_DEBUG << "RemoteCursor::next k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return KeyValue{k, v};
}

Task<KeyValue> RemoteCursor::previous() {
    const auto start_time = clock_time::now();
    auto next_message = remote::Cursor{};
    next_message.set_op(remote::Op::PREV);
    next_message.set_cursor(cursor_id_);
    auto next_pair = co_await tx_rpc_.write_and_read(next_message);
    const auto k = silkworm::bytes_of_string(next_pair.k());
    const auto v = silkworm::bytes_of_string(next_pair.v());
    SILK_DEBUG << "RemoteCursor::previous k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return KeyValue{k, v};
}

Task<KeyValue> RemoteCursor::next_dup() {
    const auto start_time = clock_time::now();
    auto next_message = remote::Cursor{};
    next_message.set_op(remote::Op::NEXT_DUP);
    next_message.set_cursor(cursor_id_);
    auto next_pair = co_await tx_rpc_.write_and_read(next_message);
    const auto k = silkworm::bytes_of_string(next_pair.k());
    const auto v = silkworm::bytes_of_string(next_pair.v());
    SILK_DEBUG << "RemoteCursor::next k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return KeyValue{k, v};
}

Task<silkworm::Bytes> RemoteCursor::seek_both(silkworm::ByteView key, silkworm::ByteView value) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "RemoteCursor::seek_both cursor: " << cursor_id_ << " key: " << key << " subkey: " << value;
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK_BOTH);
    seek_message.set_cursor(cursor_id_);
    seek_message.set_k(key.data(), key.length());
    seek_message.set_v(value.data(), value.length());
    auto seek_pair = co_await tx_rpc_.write_and_read(seek_message);
    const auto k = silkworm::bytes_of_string(seek_pair.k());
    const auto v = silkworm::bytes_of_string(seek_pair.v());
    SILK_DEBUG << "RemoteCursor::seek_both k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return v;
}

Task<KeyValue> RemoteCursor::seek_both_exact(silkworm::ByteView key, silkworm::ByteView value) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "RemoteCursor::seek_both_exact cursor: " << cursor_id_ << " key: " << key << " subkey: " << value;
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK_BOTH_EXACT);
    seek_message.set_cursor(cursor_id_);
    seek_message.set_k(key.data(), key.length());
    seek_message.set_v(value.data(), value.length());
    auto seek_pair = co_await tx_rpc_.write_and_read(seek_message);
    const auto k = silkworm::bytes_of_string(seek_pair.k());
    const auto v = silkworm::bytes_of_string(seek_pair.v());
    SILK_DEBUG << "RemoteCursor::seek_both_exact k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return KeyValue{k, v};
}

Task<void> RemoteCursor::close_cursor() {
    const auto start_time = clock_time::now();
    const auto cursor_id = cursor_id_;
    if (cursor_id_ != 0) {
        SILK_DEBUG << "RemoteCursor::close_cursor closing cursor: " << cursor_id_;
        auto close_message = remote::Cursor{};
        close_message.set_op(remote::Op::CLOSE);
        close_message.set_cursor(cursor_id_);
        co_await tx_rpc_.write_and_read(close_message);
        SILK_DEBUG << "RemoteCursor::close_cursor cursor: " << cursor_id_;
        cursor_id_ = 0;
    }
    SILK_DEBUG << "RemoteCursor::close_cursor c=" << cursor_id << " t=" << clock_time::since(start_time);
    co_return;
}

}  // namespace silkworm::rpc::ethdb::kv
