// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_factory.hpp"

#include <silkworm/db/kv/api/local_transaction.hpp>
#include <silkworm/db/kv/grpc/client/remote_transaction.hpp>

#include "local_state.hpp"
#include "remote_state.hpp"

namespace silkworm::execution {

std::shared_ptr<State> StateFactory::make(
    boost::asio::any_io_executor& executor,
    const db::chain::ChainStorage& storage,
    std::optional<TxnId> txn_id) const {
    if (tx.is_local()) {
        const auto& local_tx = dynamic_cast<db::kv::api::LocalTransaction&>(tx);
        return std::make_shared<LocalState>(txn_id, local_tx.data_store());
    } else {  // NOLINT(readability-else-after-return)
        return std::make_shared<RemoteState>(executor, tx, storage, txn_id);
    }
}

}  // namespace silkworm::execution
