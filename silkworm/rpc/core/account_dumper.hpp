// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/dump_account.hpp>

namespace silkworm::rpc::core {

using db::kv::api::KeyValue;

class AccountDumper {
  public:
    explicit AccountDumper(db::kv::api::Transaction& transaction) : transaction_(transaction) {}

    AccountDumper(const AccountDumper&) = delete;
    AccountDumper& operator=(const AccountDumper&) = delete;

    Task<DumpAccounts> dump_accounts(
        BlockCache& cache,
        const BlockNumOrHash& block_num_or_hash,
        const evmc::address& start_address,
        int16_t max_result,
        bool exclude_code,
        bool exclude_storage);

  private:
    Task<void> load_storage(BlockNum block_num, DumpAccounts& dump_accounts);

    db::kv::api::Transaction& transaction_;
};

}  // namespace silkworm::rpc::core
