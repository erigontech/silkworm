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

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/remote/kv/api/util.hpp>

#include "../../api/cursor.hpp"
#include "rpc.hpp"

namespace silkworm::db::kv::grpc::client {

class RemoteCursor : public api::CursorDupSort {
  public:
    explicit RemoteCursor(TxRpc& tx_rpc) : tx_rpc_(tx_rpc), cursor_id_{0} {}

    uint32_t cursor_id() const override { return cursor_id_; };

    Task<void> open_cursor(const std::string& table_name, bool is_dup_sorted) override;

    Task<api::KeyValue> seek(ByteView key) override;

    Task<api::KeyValue> seek_exact(ByteView key) override;

    Task<api::KeyValue> next() override;

    Task<api::KeyValue> previous() override;

    Task<api::KeyValue> next_dup() override;

    Task<void> close_cursor() override;

    Task<Bytes> seek_both(ByteView key, ByteView value) override;

    Task<api::KeyValue> seek_both_exact(ByteView key, ByteView value) override;

  private:
    TxRpc& tx_rpc_;
    uint32_t cursor_id_;
};

}  // namespace silkworm::db::kv::grpc::client
