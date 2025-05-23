// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call_many.hpp"

#include <memory>
#include <sstream>
#include <string>

#include <evmc/instructions.h>

#include <silkworm/execution/state_factory.hpp>
#include <silkworm/infra/common/clock_time.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/async_task.hpp>
#include <silkworm/rpc/common/compatibility.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/core/override_state.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::call {

CallManyResult CallExecutor::executes_all_bundles(const silkworm::ChainConfig& config,
                                                  const ChainStorage& storage,
                                                  const std::shared_ptr<BlockWithHash>& block_with_hash,
                                                  const Bundles& bundles,
                                                  std::optional<std::uint64_t> opt_timeout,
                                                  const AccountsOverrides& accounts_overrides,
                                                  std::optional<TxnId> txn_id,
                                                  boost::asio::any_io_executor& this_executor) {
    CallManyResult result;
    const auto& block = block_with_hash->block;
    auto state = execution::StateFactory{transaction_}.make(this_executor, storage, txn_id);
    EVMExecutor executor{block, config, workers_, std::make_shared<state::OverrideState>(*state, accounts_overrides)};

    uint64_t timeout = opt_timeout.value_or(5000);
    const auto start_time = clock_time::now();

    // Don't call reserve here to preallocate result.results - since json value is dynamic it doesn't know yet how much it should allocate!
    // -> Don't uncomment this line result.results.reserve(bundles.size());
    for (const auto& bundle : bundles) {
        const auto& block_override = bundle.block_override;

        // creates a block copy where overrides few values
        auto block_with_hash_shared_copy = std::make_shared<BlockWithHash>();
        *block_with_hash_shared_copy = *block_with_hash;

        rpc::Block block_context{{block_with_hash_shared_copy}};
        if (block_override.block_num) {
            block_context.block_with_hash->block.header.number = block_override.block_num.value();
        }
        if (block_override.coin_base) {
            block_context.block_with_hash->block.header.beneficiary = block_override.coin_base.value();
        }
        if (block_override.timestamp) {
            block_context.block_with_hash->block.header.timestamp = block_override.timestamp.value();
        }
        if (block_override.difficulty) {
            block_context.block_with_hash->block.header.difficulty = block_override.difficulty.value();
        }
        if (block_override.gas_limit) {
            block_context.block_with_hash->block.header.gas_limit = block_override.gas_limit.value();
        }
        if (block_override.base_fee) {
            block_context.block_with_hash->block.header.base_fee_per_gas = block_override.base_fee;
        }

        std::vector<nlohmann::json> results;
        // Don't call reserve here to preallocate result.results - since json value is dynamic it doesn't know yet how much it should allocate!
        // -> Don't uncomment this line result.results.reserve(bundle.transactions.size());
        for (const auto& call : bundle.transactions) {
            silkworm::Transaction txn{call.to_transaction()};

            auto call_execution_result = executor.call(txn);

            if (call_execution_result.pre_check_error) {
                result.error = call_execution_result.pre_check_error;
                return result;
            }

            if ((clock_time::since(start_time) / 1000000) > timeout) {
                std::ostringstream oss;
                oss << "execution aborted (timeout = " << static_cast<double>(timeout) / 1000.0 << "s)";
                result.error = oss.str();
                return result;
            }

            nlohmann::json reply;
            if (call_execution_result.status_code == evmc_status_code::EVMC_SUCCESS) {
                if (rpc::compatibility::is_erigon_json_api_compatibility_required()) {
                    reply["value"] = silkworm::to_hex(call_execution_result.data);
                } else {
                    reply["value"] = "0x" + silkworm::to_hex(call_execution_result.data);
                }
            } else {
                const auto error_message = call_execution_result.error_message();
                if (call_execution_result.data.empty()) {
                    reply["error"] = error_message;
                } else if (rpc::compatibility::is_erigon_json_api_compatibility_required()) {
                    reply["error"] = nlohmann::json::object();
                } else {
                    RevertError revert_error{{3, error_message}, call_execution_result.data};
                    reply = revert_error;
                }
            }

            results.push_back(reply);
        }
        result.results.push_back(results);
    }
    return result;
}

Task<CallManyResult> CallExecutor::execute(
    const Bundles& bundles,
    const SimulationContext& context,
    const AccountsOverrides& accounts_overrides,
    std::optional<std::uint64_t> timeout) {
    const auto chain_storage{transaction_.make_storage()};

    uint16_t count{0};
    bool empty = true;
    for (const auto& bundle : bundles) {
        SILK_DEBUG << "bundle[" << count++ << "]: " << bundle;
        if (!bundle.transactions.empty()) {
            empty = false;
        }
    }
    CallManyResult result;
    if (empty) {
        result.error = "empty all bundles transactions";
        co_return result;
    }

    const auto chain_config = co_await chain_storage->read_chain_config();
    const auto block_with_hash = co_await block_reader_.read_block_by_block_num_or_hash(block_cache_, context.block_num);
    if (!block_with_hash) {
        throw std::invalid_argument("read_block_by_block_num_or_hash: block not found");
    }

    auto this_executor = co_await boost::asio::this_coro::executor;

    std::optional<TxnId> txn_id;

    if (!co_await block_reader_.is_latest_block_num(block_with_hash->block.header.number)) {
        const uint32_t transaction_index =
            context.transaction_index == -1 ? static_cast<uint32_t>(block_with_hash->block.transactions.size()) : static_cast<uint32_t>(context.transaction_index);
        txn_id = co_await transaction_.user_txn_id_at(block_with_hash->block.header.number, transaction_index);
    }
    result = co_await async_task(workers_.executor(), [&]() -> CallManyResult {
        return executes_all_bundles(chain_config,
                                    *chain_storage,
                                    block_with_hash,
                                    bundles,
                                    timeout,
                                    accounts_overrides,
                                    txn_id,
                                    this_executor);
    });

    co_return result;
}

}  // namespace silkworm::rpc::call
