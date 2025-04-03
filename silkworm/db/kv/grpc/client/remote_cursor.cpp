// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "remote_cursor.hpp"

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/common/clock_time.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/common/errors.hpp>
#include <silkworm/infra/grpc/common/util.hpp>
#include <silkworm/interfaces/remote/kv.pb.h>

namespace silkworm::db::kv::grpc::client {

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
        cursor_id_ = (co_await write_and_read(open_message)).cursor_id();
        SILK_DEBUG << "RemoteCursor::open_cursor cursor: " << cursor_id_ << " for table: " << table_name;
    }
    SILK_DEBUG << "RemoteCursor::open_cursor [" << table_name << "] c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return;
}

Task<api::KeyValue> RemoteCursor::seek(ByteView key) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "RemoteCursor::seek cursor: " << cursor_id_ << " key: " << key;
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK);
    seek_message.set_cursor(cursor_id_);
    seek_message.set_k(key.data(), key.size());
    auto seek_pair = co_await write_and_read(seek_message);
    auto k = string_to_bytes(seek_pair.k());
    auto v = string_to_bytes(seek_pair.v());
    SILK_DEBUG << "RemoteCursor::seek k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return api::KeyValue{std::move(k), std::move(v)};
}

Task<api::KeyValue> RemoteCursor::seek_exact(ByteView key) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "RemoteCursor::seek_exact cursor: " << cursor_id_ << " key: " << key;
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK_EXACT);
    seek_message.set_cursor(cursor_id_);
    seek_message.set_k(key.data(), key.size());
    auto seek_pair = co_await write_and_read(seek_message);
    auto k = string_to_bytes(seek_pair.k());
    auto v = string_to_bytes(seek_pair.v());
    SILK_DEBUG << "RemoteCursor::seek_exact k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return api::KeyValue{std::move(k), std::move(v)};
}

Task<api::KeyValue> RemoteCursor::first() {
    const auto start_time = clock_time::now();
    auto next_message = remote::Cursor{};
    next_message.set_op(remote::Op::FIRST);
    next_message.set_cursor(cursor_id_);
    auto first_pair = co_await write_and_read(next_message);
    auto k = string_to_bytes(first_pair.k());
    auto v = string_to_bytes(first_pair.v());
    SILK_DEBUG << "RemoteCursor::first k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return api::KeyValue{std::move(k), std::move(v)};
}

Task<api::KeyValue> RemoteCursor::last() {
    const auto start_time = clock_time::now();
    auto next_message = remote::Cursor{};
    next_message.set_op(remote::Op::LAST);
    next_message.set_cursor(cursor_id_);
    auto last_pair = co_await write_and_read(next_message);
    auto k = string_to_bytes(last_pair.k());
    auto v = string_to_bytes(last_pair.v());
    SILK_DEBUG << "RemoteCursor::last k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return api::KeyValue{std::move(k), std::move(v)};
}

Task<api::KeyValue> RemoteCursor::next() {
    const auto start_time = clock_time::now();
    auto next_message = remote::Cursor{};
    next_message.set_op(remote::Op::NEXT);
    next_message.set_cursor(cursor_id_);
    auto next_pair = co_await write_and_read(next_message);
    auto k = string_to_bytes(next_pair.k());
    auto v = string_to_bytes(next_pair.v());
    SILK_DEBUG << "RemoteCursor::next k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return api::KeyValue{std::move(k), std::move(v)};
}

Task<api::KeyValue> RemoteCursor::previous() {
    const auto start_time = clock_time::now();
    auto next_message = remote::Cursor{};
    next_message.set_op(remote::Op::PREV);
    next_message.set_cursor(cursor_id_);
    auto next_pair = co_await write_and_read(next_message);
    auto k = string_to_bytes(next_pair.k());
    auto v = string_to_bytes(next_pair.v());
    SILK_DEBUG << "RemoteCursor::previous k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return api::KeyValue{std::move(k), std::move(v)};
}

Task<api::KeyValue> RemoteCursor::next_dup() {
    const auto start_time = clock_time::now();
    auto next_message = remote::Cursor{};
    next_message.set_op(remote::Op::NEXT_DUP);
    next_message.set_cursor(cursor_id_);
    auto next_pair = co_await write_and_read(next_message);
    auto k = string_to_bytes(next_pair.k());
    auto v = string_to_bytes(next_pair.v());
    SILK_DEBUG << "RemoteCursor::next k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return api::KeyValue{std::move(k), std::move(v)};
}

Task<Bytes> RemoteCursor::seek_both(ByteView key, ByteView value) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "RemoteCursor::seek_both cursor: " << cursor_id_ << " key: " << key << " subkey: " << value;
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK_BOTH);
    seek_message.set_cursor(cursor_id_);
    seek_message.set_k(key.data(), key.size());
    seek_message.set_v(value.data(), value.size());
    auto seek_pair = co_await write_and_read(seek_message);
    const auto k = string_to_bytes(seek_pair.k());
    const auto v = string_to_bytes(seek_pair.v());
    SILK_DEBUG << "RemoteCursor::seek_both k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return v;
}

Task<api::KeyValue> RemoteCursor::seek_both_exact(ByteView key, ByteView value) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "RemoteCursor::seek_both_exact cursor: " << cursor_id_ << " key: " << key << " subkey: " << value;
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK_BOTH_EXACT);
    seek_message.set_cursor(cursor_id_);
    seek_message.set_k(key.data(), key.size());
    seek_message.set_v(value.data(), value.size());
    auto seek_pair = co_await write_and_read(seek_message);
    auto k = string_to_bytes(seek_pair.k());
    auto v = string_to_bytes(seek_pair.v());
    SILK_DEBUG << "RemoteCursor::seek_both_exact k: " << k << " v: " << v << " c=" << cursor_id_ << " t=" << clock_time::since(start_time);
    co_return api::KeyValue{std::move(k), std::move(v)};
}

Task<void> RemoteCursor::close_cursor() {
    const auto start_time = clock_time::now();
    const auto cursor_id = cursor_id_;
    if (cursor_id_ != 0) {
        SILK_DEBUG << "RemoteCursor::close_cursor closing cursor: " << cursor_id_;
        auto close_message = remote::Cursor{};
        close_message.set_op(remote::Op::CLOSE);
        close_message.set_cursor(cursor_id_);
        co_await write_and_read(close_message);
        SILK_DEBUG << "RemoteCursor::close_cursor cursor: " << cursor_id_;
        cursor_id_ = 0;
    }
    SILK_DEBUG << "RemoteCursor::close_cursor c=" << cursor_id << " t=" << clock_time::since(start_time);
    co_return;
}

Task<::remote::Pair> RemoteCursor::write_and_read(const ::remote::Cursor& request) {
    if (!co_await tx_rpc_.write(request)) {
        const ::grpc::Status status = co_await tx_rpc_.finish();
        SILK_TRACE << "Tx RPC write failed status=" << status;
        throw boost::system::system_error{rpc::to_system_code(status.error_code())};
    }
    TxRpc::Response kv_pair{};
    if (!co_await tx_rpc_.read(kv_pair)) {
        const ::grpc::Status status = co_await tx_rpc_.finish();
        SILK_TRACE << "Tx RPC read failed status=" << status;
        throw boost::system::system_error{rpc::to_system_code(status.error_code())};
    }
    co_return kv_pair;
}

}  // namespace silkworm::db::kv::grpc::client
