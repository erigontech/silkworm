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

#include <string>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/types/call.hpp>

namespace silkworm::rpc::call {

struct CallManyResult {
    std::optional<std::string> error{std::nullopt};
    std::vector<std::vector<nlohmann::json>> results;
};

class CallExecutor {
  public:
    CallExecutor(
        db::kv::api::Transaction& transaction,
        db::kv::api::StateCache* state_cache,
        BlockCache& block_cache,
        WorkerPool& workers,
        rpc::BlockReader& block_reader)
        : transaction_(transaction),
          state_cache_(state_cache),
          block_cache_(block_cache),
          workers_{workers},
          block_reader_{block_reader} {}
    virtual ~CallExecutor() = default;

    CallExecutor(const CallExecutor&) = delete;
    CallExecutor& operator=(const CallExecutor&) = delete;

    Task<CallManyResult> execute(
        const Bundles& bundles,
        const SimulationContext& context,
        const AccountsOverrides& accounts_overrides,
        std::optional<std::uint64_t> timeout);

    CallManyResult executes_all_bundles(const silkworm::ChainConfig& config,
                                        const ChainStorage& storage,
                                        const std::shared_ptr<BlockWithHash>& block_with_hash,
                                        const Bundles& bundles,
                                        std::optional<std::uint64_t> opt_timeout,
                                        const AccountsOverrides& accounts_overrides,
                                        std::optional<TxnId> txn_id,
                                        boost::asio::any_io_executor& executor);

  private:
    db::kv::api::Transaction& transaction_;
    db::kv::api::StateCache* state_cache_;
    BlockCache& block_cache_;
    WorkerPool& workers_;
    rpc::BlockReader& block_reader_;
};
}  // namespace silkworm::rpc::call
