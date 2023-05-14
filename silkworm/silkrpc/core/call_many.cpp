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

#include "call_many.hpp"

#include <memory>
#include <string>

#include <evmc/hex.hpp>
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>
#include <intx/intx.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/ethdb/kv/cached_database.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc::call {

using boost::asio::awaitable;

void to_json(nlohmann::json& json, const CallManyResult& /*result*/) {
    json = nlohmann::json::object();
}

boost::asio::awaitable<CallManyResult> CallExecutor::execute(const Bundles& bundles, const SimulationContext& context,
                                                             const StateOverrides& /*state_overrides*/, std::optional<std::uint64_t> /*timeout*/) {
    ethdb::TransactionDatabase tx_database{transaction_};
    ethdb::kv::CachedDatabase cached_database{context.block_number, transaction_, state_cache_};

    const auto chain_id = co_await core::rawdb::read_chain_id(tx_database);
    /*const auto chain_config_ptr = */ lookup_chain_config(chain_id);

    // const auto [block_number, is_latest_block] = co_await rpc::core::get_block_number(context.block_number, tx_database, /*latest_required=*/true);
    // state::RemoteState remote_state{io_context_,
    //                                 is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database),
    //                                 block_number};
    CallManyResult result;
    std::uint16_t count{0};
    for (const auto& bundle : bundles) {
        SILKRPC_DEBUG << "bundle[" << count++ << "]: " << bundle << "\n";
        if (bundle.transactions.size() > 0) {
            result.error = "empty all bundles transactions";
            co_return result;
        }
    }
    co_return result;
}

}  // namespace silkworm::rpc::call
