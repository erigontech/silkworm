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

#pragma once

#include <memory>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/transaction.hpp>

namespace silkworm::execution {

struct StateFactory {
    db::kv::api::Transaction& tx;

    std::shared_ptr<State> create_state(
        boost::asio::any_io_executor& executor,
        const db::chain::ChainStorage& storage,
        TxnId txn_id);
};

}  // namespace silkworm::execution
