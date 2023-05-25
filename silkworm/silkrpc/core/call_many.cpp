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
#include <silkworm/silkrpc/core/override_state.hpp>
#include <silkworm/silkrpc/core/remote_state.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/ethdb/kv/cached_database.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc::call {

using boost::asio::awaitable;

// void to_json(nlohmann::json& json, const CallResult& result) {
//     if (result.error) {
//         json["error"] = result.error.value();
//     } else {
//         json["result"] = result.data;
//     }
// }

boost::asio::awaitable<CallManyResult> CallExecutor::execute(const Bundles& bundles, const SimulationContext& context,
                                                             const StateOverrides& /*state_overrides*/, std::optional<std::uint64_t> /*timeout*/) {
    ethdb::TransactionDatabase tx_database{transaction_};
    // ethdb::kv::CachedDatabase cached_database{context.block_number, transaction_, state_cache_};

    std::uint16_t count{0};
    bool empty = true;
    for (const auto& bundle : bundles) {
        SILK_DEBUG << "bundle[" << count++ << "]: " << bundle << "\n";
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

    // const auto [block_number, is_latest_block] = co_await rpc::core::get_block_number(context.block_number, tx_database, /*latest_required=*/true);
    // co_await rpc::core::read_block_by_number(block_cache_, tx_database, block_number);
    const auto block_with_hash = co_await rpc::core::read_block_by_number_or_hash(block_cache_, tx_database, context.block_number);
    auto transaction_index = context.transaction_index;
    auto block_number = block_with_hash->block.header.number;
    const auto& block = block_with_hash->block;
    const auto& block_transactions = block.transactions;

    rpc::Block initial_block{block};
    std::cout << "***********  initial_block: " << initial_block << "\n";
    std::cout << "***********  transaction size: " << block_transactions.size() << "\n";

    if (transaction_index == -1) {
        transaction_index = block_transactions.size();
    }

    // std::vector<Transaction> transactions(block_transactions.begin(), block_transactions.begin() + transaction_index);
    state::RemoteState remote_state{io_context_, tx_database, block_number};
    state::OverrideState state{remote_state};

    const auto chain_config_ptr = lookup_chain_config(chain_id);

    EVMExecutor executor{*chain_config_ptr, workers_, state};

    std::cout << "***********  transaction_index: " << transaction_index << "\n";
    for (auto idx{0}; idx < transaction_index; idx++) {
        silkworm::Transaction txn{block_transactions[std::size_t(idx)]};

        rpc::Transaction trans{txn};
        std::cout << "*********** " << idx << "  transaction: " << trans << "\n";

        if (!txn.from) {
            txn.recover_sender();
        }
        co_await executor.call(block, txn);
    }
    executor.reset();

    // state::RemoteState remote_state{io_context_,
    //                                 is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database),
    //                                 block_number};

    result.results.reserve(bundles.size());
    for (const auto& bundle : bundles) {
        const auto& block_override = bundle.block_override;

        rpc::Block blockContext{block_with_hash->block};
        std::cout << "***********  blockContext: " << blockContext << "\n";
        nlohmann::json json = blockContext;
        if (block_override.block_number) {
            blockContext.block.header.number = block_override.block_number.value();
        }
        // if (block_override.coin_base) {
        //     blockContext.header.number = block_override.coin_base.value();
        // }
        if (block_override.timestamp) {
            // blockContext.header.timestamp = block_override.timestamp.value();
        }
        if (block_override.difficulty) {
            // blockContext.header.difficulty = block_override.difficulty.value();
        }
        if (block_override.gas_limit) {
            // blockContext.header.gas_limit = block_override.gas_limit.value();
        }
        if (block_override.base_fee) {
            // blockContext.header.base_fee_per_gas = block_override.base_fee;
        }
        // block_hash
        std::cout << "***********  blockContext dopo override: " << blockContext << "\n";

        std::vector<nlohmann::json> results;
        result.results.reserve(bundle.transactions.size());
        for (const auto& call : bundle.transactions) {
            silkworm::Transaction txn{call.to_transaction()};

            rpc::Transaction trans{txn};
            std::cout << "*********** transaction from call: " << trans << "\n";

            auto execution_result = co_await executor.call(blockContext.block, txn);

            if (execution_result.pre_check_error) {
                std::cout << "***********  fallimento per pre-check\n";
                result.error = execution_result.pre_check_error;
                co_return result;
            }

            nlohmann::json reply;
            if (execution_result.error_code == evmc_status_code::EVMC_SUCCESS) {
                reply["value"] = "0x" + silkworm::to_hex(execution_result.data);
            } else {
                const auto error_message = EVMExecutor::get_error_message(execution_result.error_code, execution_result.data);
                if (execution_result.data.empty()) {
                    reply["error"]["code"] = -32000;
                    reply["error"]["message"] = error_message;
                } else {
                    RevertError revert_error{3, error_message, execution_result.data};
                    reply = revert_error;
                }
            }

            // CallResult cr{execution_result.error_code, execution_result.data};
            results.push_back(reply);
        }
        result.results.push_back(results);
    }
    co_return result;
}

}  // namespace silkworm::rpc::call
