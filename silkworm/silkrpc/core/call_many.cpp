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

#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/core/override_state.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/core/remote_state.hpp>
#include <silkworm/silkrpc/ethdb/kv/cached_database.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc::call {

using boost::asio::awaitable;

boost::asio::awaitable<CallManyResult> CallExecutor::execute(const Bundles& bundles, const SimulationContext& context,
                                                             const AccountsOverrides& accounts_overrides, std::optional<std::uint64_t> /*timeout*/) {
    ethdb::TransactionDatabase tx_database{transaction_};

    std::uint16_t count{0};
    bool empty = true;
    for (const auto& bundle : bundles) {
        SILK_DEBUG << "bundle[" << count++ << "]: " << bundle;
        if (bundle.transactions.size() > 0) {
            empty = false;
        }
    }
    CallManyResult result;
    if (empty) {
        result.error = "empty all bundles transactions";
        co_return result;
    }

    const auto chain_id = co_await core::rawdb::read_chain_id(tx_database);

    const auto block_with_hash = co_await rpc::core::read_block_by_number_or_hash(block_cache_, tx_database, context.block_number);
    auto transaction_index = context.transaction_index;
    auto block_number = block_with_hash->block.header.number;
    const auto& block = block_with_hash->block;
    const auto& block_transactions = block.transactions;

    if (transaction_index == -1) {
        transaction_index = block_transactions.size();
    }

    auto state = co_await transaction_.create_state(tx_database, block_number);
    state::OverrideState override_state{*state, accounts_overrides};

    const auto chain_config_ptr = lookup_chain_config(chain_id);

    EVMExecutor executor{*chain_config_ptr, workers_, override_state};

    for (auto idx{0}; idx < transaction_index; idx++) {
        silkworm::Transaction txn{block_transactions[std::size_t(idx)]};

        if (!txn.from) {
            txn.recover_sender();
        }
        co_await executor.call(block, txn);
    }
    executor.reset();

    result.results.reserve(bundles.size());
    for (const auto& bundle : bundles) {
        const auto& block_override = bundle.block_override;

        rpc::Block blockContext{block_with_hash->block};
        if (block_override.block_number) {
            blockContext.block.header.number = block_override.block_number.value();
        }
        if (block_override.coin_base) {
            // blockContext.block.header.number = block_override.coin_base.value();
        }
        if (block_override.timestamp) {
            blockContext.block.header.timestamp = block_override.timestamp.value();
        }
        if (block_override.difficulty) {
            blockContext.block.header.difficulty = block_override.difficulty.value();
        }
        if (block_override.gas_limit) {
            blockContext.block.header.gas_limit = block_override.gas_limit.value();
        }
        if (block_override.base_fee) {
            blockContext.block.header.base_fee_per_gas = block_override.base_fee;
        }

        std::vector<nlohmann::json> results;
        result.results.reserve(bundle.transactions.size());
        for (const auto& call : bundle.transactions) {
            silkworm::Transaction txn{call.to_transaction()};

            auto execution_result = co_await executor.call(blockContext.block, txn);

            if (execution_result.pre_check_error) {
                result.error = execution_result.pre_check_error;
                co_return result;
            }

            nlohmann::json reply;
            if (execution_result.error_code == evmc_status_code::EVMC_SUCCESS) {
                reply["value"] = "0x" + silkworm::to_hex(execution_result.data);
            } else {
                const auto error_message = EVMExecutor::get_error_message(execution_result.error_code, execution_result.data);
                if (execution_result.data.empty()) {
                    reply["error"] = error_message;
                } else {
                    RevertError revert_error{3, error_message, execution_result.data};
                    reply = revert_error;
                }
            }

            results.push_back(reply);
        }
        result.results.push_back(results);
    }
    co_return result;
}

}  // namespace silkworm::rpc::call
