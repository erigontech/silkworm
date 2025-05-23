// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/types/block.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/types/receipt.hpp>

namespace silkworm::rpc::core {

Task<std::shared_ptr<Receipts>> get_receipts(db::kv::api::Transaction& tx,
                                             const silkworm::BlockWithHash& block_with_hash,
                                             const db::chain::ChainStorage& chain_storage,
                                             WorkerPool& workers,
                                             bool extended_receipt_info = true);

Task<std::shared_ptr<Receipts>> read_receipts(db::kv::api::Transaction& tx, BlockNum block_num);

Task<std::shared_ptr<Receipts>> generate_receipts(db::kv::api::Transaction& tx,
                                                  const silkworm::Block& block,
                                                  const db::chain::ChainStorage& chain_storage,
                                                  WorkerPool& workers);

Task<std::shared_ptr<Receipt>> get_receipt(db::kv::api::Transaction& tx,
                                           const silkworm::Block& block,
                                           TxnId txn_id,
                                           uint32_t tx_index,
                                           const silkworm::Transaction& transaction,
                                           const db::chain::ChainStorage& chain_storage,
                                           WorkerPool& workers);

Task<std::shared_ptr<Receipts>> get_cached_receipts(const evmc::bytes32& hash);

}  // namespace silkworm::rpc::core
