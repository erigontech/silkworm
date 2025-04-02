// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/use_awaitable.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/interfaces/remote/kv.pb.h>

#include "../../api/cursor.hpp"
#include "rpc.hpp"

namespace silkworm::db::kv::grpc::client {

class RemoteCursor : public api::CursorDupSort {
  public:
    explicit RemoteCursor(TxRpc& tx_rpc) : tx_rpc_(tx_rpc) {}

    uint32_t cursor_id() const override { return cursor_id_; };

    Task<void> open_cursor(std::string_view table_name, bool is_dup_sorted) override;

    Task<api::KeyValue> seek(ByteView key) override;

    Task<api::KeyValue> seek_exact(ByteView key) override;

    Task<api::KeyValue> first() override;

    Task<api::KeyValue> last() override;

    Task<api::KeyValue> next() override;

    Task<api::KeyValue> previous() override;

    Task<api::KeyValue> next_dup() override;

    Task<void> close_cursor() override;

    Task<Bytes> seek_both(ByteView key, ByteView value) override;

    Task<api::KeyValue> seek_both_exact(ByteView key, ByteView value) override;

  private:
    Task<::remote::Pair> write_and_read(const ::remote::Cursor& request);

    TxRpc& tx_rpc_;
    uint32_t cursor_id_{0};
};

}  // namespace silkworm::db::kv::grpc::client
