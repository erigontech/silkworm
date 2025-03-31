// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/db/kv/api/transaction.hpp>

namespace silkworm::rpc {

silkworm::Bytes make_key(const evmc::address& address, const evmc::bytes32& location);

class StorageWalker {
  public:
    using AccountCollector = std::function<bool(const evmc::address&, silkworm::ByteView, silkworm::ByteView)>;
    using StorageCollector = std::function<bool(const silkworm::ByteView, silkworm::ByteView, silkworm::ByteView)>;

    explicit StorageWalker(db::kv::api::Transaction& transaction) : transaction_(transaction) {}

    StorageWalker(const StorageWalker&) = delete;
    StorageWalker& operator=(const StorageWalker&) = delete;

    Task<void> storage_range_at(
        TxnId txn_number,
        const evmc::address& address,
        const evmc::bytes32& start_location,
        StorageCollector& collector);

  private:
    db::kv::api::Transaction& transaction_;
};

}  // namespace silkworm::rpc
