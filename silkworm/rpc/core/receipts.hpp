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

#include <silkworm/core/types/block.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/types/receipt.hpp>

namespace silkworm::rpc::core {

Task<Receipts> get_receipts(db::kv::api::Transaction& tx,
                            const silkworm::BlockWithHash& block_with_hash,
                            const db::chain::ChainStorage& chain_storage,
                            WorkerPool& workers,
                            bool extended_receipt_info = true);

Task<std::optional<Receipts>> read_receipts(db::kv::api::Transaction& tx, BlockNum block_num);

Task<std::optional<Receipts>> generate_receipts(db::kv::api::Transaction& tx,
                                                const silkworm::Block& block,
                                                const db::chain::ChainStorage& chain_storage,
                                                WorkerPool& workers);

Task<std::optional<Receipt>> get_receipt(db::kv::api::Transaction& tx,
                                         const silkworm::Block& block,
                                         TxnId txn_id,
                                         uint32_t tx_index,
                                         const silkworm::Transaction& transaction,
                                         const db::chain::ChainStorage& chain_storage,
                                         WorkerPool& workers);

}  // namespace silkworm::rpc::core
