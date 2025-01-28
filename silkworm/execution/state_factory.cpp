/*
   Copyright 2024 The Silkworm Authors

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

#include "state_factory.hpp"

#include <silkworm/db/kv/api/local_transaction.hpp>
#include <silkworm/db/kv/grpc/client/remote_transaction.hpp>

#include "local_state.hpp"
#include "remote_state.hpp"

namespace silkworm::execution {

std::shared_ptr<State> StateFactory::create_state(
    boost::asio::any_io_executor& executor,
    const db::chain::ChainStorage& storage,
    std::optional<TxnId> txn_id) {
    if (tx.is_local()) {
        auto& local_tx = dynamic_cast<db::kv::api::LocalTransaction&>(tx);
        return std::make_shared<LocalState>(txn_id, local_tx.data_store());
    } else {  // NOLINT(readability-else-after-return)
        return std::make_shared<RemoteState>(executor, tx, storage, txn_id);
    }
}

}  // namespace silkworm::execution
