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

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc::core {

// TODO(canepat) move to BlockReader or BlockReaderWithCache

Task<std::shared_ptr<BlockWithHash>> read_block_by_number(BlockCache& cache,
                                                          const db::chain::ChainStorage& storage,
                                                          BlockNum block_num);
Task<std::shared_ptr<BlockWithHash>> read_block_by_hash(BlockCache& cache,
                                                        const db::chain::ChainStorage& storage,
                                                        const evmc::bytes32& block_hash);
Task<std::shared_ptr<BlockWithHash>> read_block_by_block_num_or_hash(BlockCache& cache,
                                                                     const db::chain::ChainStorage& storage,
                                                                     db::kv::api::Transaction& tx,
                                                                     db::kv::api::StateCache* state_cache,
                                                                     const BlockNumOrHash& block_num_or_hash);
Task<std::shared_ptr<BlockWithHash>> read_block_by_transaction_hash(BlockCache& cache,
                                                                    const db::chain::ChainStorage& storage,
                                                                    const evmc::bytes32& transaction_hash);
Task<std::optional<TransactionWithBlock>> read_transaction_by_hash(BlockCache& cache,
                                                                   const db::chain::ChainStorage& storage,
                                                                   const evmc::bytes32& transaction_hash);

}  // namespace silkworm::rpc::core
