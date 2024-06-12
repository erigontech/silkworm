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

#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/rpc/ethdb/base_transaction.hpp>
#include <silkworm/rpc/ethdb/cursor.hpp>
#include <silkworm/rpc/ethdb/file/local_cursor.hpp>

namespace silkworm::rpc::ethdb::file {

class LocalTransaction : public BaseTransaction {
  public:
    explicit LocalTransaction(mdbx::env chaindata_env, kv::StateCache* state_cache)
        : BaseTransaction(state_cache), chaindata_env_{std::move(chaindata_env)}, last_cursor_id_{0}, txn_{chaindata_env_} {}

    ~LocalTransaction() override = default;

    [[nodiscard]] uint64_t tx_id() const override { return tx_id_; }
    [[nodiscard]] uint64_t view_id() const override { return txn_.id(); }

    Task<void> open() override;

    Task<std::shared_ptr<Cursor>> cursor(const std::string& table) override;

    Task<std::shared_ptr<CursorDupSort>> cursor_dup_sort(const std::string& table) override;

    std::shared_ptr<silkworm::State> create_state(boost::asio::any_io_executor& executor, const ChainStorage& storage, BlockNum block_number) override;

    std::shared_ptr<ChainStorage> create_storage(ethbackend::BackEnd* backend) override;

    Task<void> close() override;

  private:
    Task<std::shared_ptr<CursorDupSort>> get_cursor(const std::string& table, bool is_cursor_dup_sort);

    static inline uint64_t next_tx_id_{0};

    std::map<std::string, std::shared_ptr<CursorDupSort>> cursors_;
    std::map<std::string, std::shared_ptr<CursorDupSort>> dup_cursors_;

    mdbx::env chaindata_env_;
    uint32_t last_cursor_id_;
    db::ROTxnManaged txn_;
    uint64_t tx_id_{++next_tx_id_};
};

}  // namespace silkworm::rpc::ethdb::file
