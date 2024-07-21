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

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/db/chain/chain_storage.hpp>

#include "cursor.hpp"
#include "endpoint/key_value.hpp"
#include "endpoint/temporal_range.hpp"

namespace silkworm::db::kv::api {

class Transaction {
  public:
    using Walker = std::function<bool(Bytes&, Bytes&)>;

    Transaction() = default;

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    virtual ~Transaction() = default;

    [[nodiscard]] virtual uint64_t tx_id() const = 0;
    [[nodiscard]] virtual uint64_t view_id() const = 0;

    virtual void set_state_cache_enabled(bool cache_enabled) = 0;

    virtual Task<void> open() = 0;

    virtual Task<std::shared_ptr<Cursor>> cursor(const std::string& table) = 0;

    virtual Task<std::shared_ptr<CursorDupSort>> cursor_dup_sort(const std::string& table) = 0;

    virtual std::shared_ptr<State> create_state(boost::asio::any_io_executor& executor, const chain::ChainStorage& storage, BlockNum block_number) = 0;

    virtual std::shared_ptr<chain::ChainStorage> create_storage() = 0;

    virtual Task<void> close() = 0;

    virtual Task<kv::api::KeyValue> get(const std::string& table, ByteView key) = 0;

    virtual Task<Bytes> get_one(const std::string& table, ByteView key) = 0;

    virtual Task<std::optional<Bytes>> get_both_range(const std::string& table, ByteView key, ByteView subkey) = 0;

    /** Temporal Range Queries **/

    // rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
    virtual Task<PaginatedTimestamps> index_range(IndexRangeQuery&& query) = 0;
};

}  // namespace silkworm::db::kv::api
