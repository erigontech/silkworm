// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>

namespace silkworm::execution {

struct StateFactory {
    db::kv::api::Transaction& tx;

    std::shared_ptr<State> create_state(
        boost::asio::any_io_executor& executor,
        const db::chain::ChainStorage& storage,
        std::optional<TxnId> txn_id) const;
};

}  // namespace silkworm::execution
