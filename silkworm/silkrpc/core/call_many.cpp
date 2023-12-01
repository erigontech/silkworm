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
#include <sstream>
#include <string>

#include <boost/asio/compose.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <evmc/hex.hpp>
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>
#include <intx/intx.hpp>

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/common/clock_time.hpp>
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

CallManyResult CallExecutor::executes_all_bundles(const silkworm::ChainConfig& config,
                                                  const ChainStorage& storage,
                                                  std::shared_ptr<BlockWithHash> block_with_hash,
                                                  ethdb::TransactionDatabase& tx_database,
                                                  const Bundles& bundles,
                                                  std::optional<std::uint64_t> opt_timeout,
                                                  const AccountsOverrides& accounts_overrides,
                                                  int32_t transaction_index,
                                                  boost::asio::any_io_executor& this_executor) {
    CallManyResult result;
    const auto& block = block_with_hash->block;
    const auto& block_transactions = block.transactions;
    auto state = transaction_.create_state(this_executor, tx_database, storage, block.header.number);
    state::OverrideState override_state{*state, accounts_overrides};
    EVMExecutor executor{config, workers_, state};

    std::uint64_t timeout = opt_timeout.value_or(5000);
    const auto start_time = clock_time::now();
    for (auto idx{0}; idx < transaction_index; idx++) {
        silkworm::Transaction txn{block_transactions[std::size_t(idx)]};

        if (!txn.from) {
            txn.recover_sender();
        }

        auto exec_result = executor.call(block, txn);

        if ((clock_time::since(start_time) / 1000000) > timeout) {
            std::ostringstream oss;
            oss << "execution aborted (timeout = " << static_cast<double>(timeout) / 1000.0 << "s)";
            result.error = oss.str();
            return result;
        }
    }
    executor.reset();

    result.results.reserve(bundles.size());
    for (const auto& bundle : bundles) {
        const auto& block_override = bundle.block_override;

        rpc::Block blockContext{{block_with_hash}};
        if (block_override.block_number) {
            blockContext.block_with_hash->block.header.number = block_override.block_number.value();
        }
        if (block_override.coin_base) {
            blockContext.block_with_hash->block.header.beneficiary = block_override.coin_base.value();
        }
        if (block_override.timestamp) {
            blockContext.block_with_hash->block.header.timestamp = block_override.timestamp.value();
        }
        if (block_override.difficulty) {
            blockContext.block_with_hash->block.header.difficulty = block_override.difficulty.value();
        }
        if (block_override.gas_limit) {
            blockContext.block_with_hash->block.header.gas_limit = block_override.gas_limit.value();
        }
        if (block_override.base_fee) {
            blockContext.block_with_hash->block.header.base_fee_per_gas = block_override.base_fee;
        }

        std::vector<nlohmann::json> results;
        result.results.reserve(bundle.transactions.size());
        for (const auto& call : bundle.transactions) {
            silkworm::Transaction txn{call.to_transaction()};

            auto call_execution_result = executor.call(blockContext.block_with_hash->block, txn);

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
            if (call_execution_result.error_code == evmc_status_code::EVMC_SUCCESS) {
                reply["value"] = "0x" + silkworm::to_hex(call_execution_result.data);
            } else {
                const auto error_message = call_execution_result.error_message();
                if (call_execution_result.data.empty()) {
                    reply["error"] = error_message;
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
    std::optional<std::uint64_t> opt_timeout) {
    ethdb::TransactionDatabase tx_database{transaction_};
    const auto chain_storage{transaction_.create_storage(tx_database, backend_)};

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

    const auto chain_config_ptr = co_await chain_storage->read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    const auto block_with_hash = co_await rpc::core::read_block_by_number_or_hash(block_cache_, *chain_storage, tx_database, context.block_number);
    if (!block_with_hash) {
        throw std::invalid_argument("read_block_by_number_or_hash: block not found");
    }
    auto transaction_index = context.transaction_index;
    if (transaction_index == -1) {
        transaction_index = static_cast<std::int32_t>(block_with_hash->block.transactions.size());
    }

    auto this_executor = co_await boost::asio::this_coro::executor;
    result = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(CallManyResult)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                result = executes_all_bundles(*chain_config_ptr, *chain_storage, block_with_hash, tx_database, bundles, opt_timeout, accounts_overrides, transaction_index, this_executor);
                boost::asio::post(this_executor, [result, self = std::move(self)]() mutable {
                    self.complete(result);
                });
            });
        },
        boost::asio::use_awaitable);

    co_return result;
}

}  // namespace silkworm::rpc::call
