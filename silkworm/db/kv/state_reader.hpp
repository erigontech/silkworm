// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/db/chain/providers.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>

#include "version.hpp"

namespace silkworm::db::kv {

class StateReader {
  public:
    StateReader(api::Transaction& tx, std::optional<TxnId> txn_id);

    StateReader(const StateReader&) = delete;
    StateReader& operator=(const StateReader&) = delete;

    Task<std::optional<Account>> read_account(const evmc::address& address) const;

    Task<evmc::bytes32> read_storage(const evmc::address& address,
                                     uint64_t incarnation,
                                     const evmc::bytes32& location_hash) const;

    Task<std::optional<Bytes>> read_code(const evmc::address& address, const evmc::bytes32& code_hash) const;

  private:
    inline Task<api::PointResult> latest_from_cache(std::string_view table, Bytes key) const;
    inline Task<api::PointResult> latest_code_from_cache(Bytes key) const;

    api::Transaction& tx_;
    std::optional<TxnId> txn_number_;
};

}  // namespace silkworm::db::kv
