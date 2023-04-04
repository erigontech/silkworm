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

#include "ots_api.hpp"

#include <numeric>
#include <string>

#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/silkrpc/consensus/ethash.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/core/receipts.hpp>
#include <silkworm/silkrpc/core/state_reader.hpp>
#include <silkworm/silkrpc/ethdb/kv/cached_database.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc::commands {

constexpr int kCurrentApiLevel{8};

boost::asio::awaitable<void> OtsRpcApi::handle_ots_get_api_level(const nlohmann::json& request, nlohmann::json& reply) {
    reply = make_json_content(request["id"], kCurrentApiLevel);
    co_return;
}

boost::asio::awaitable<void> OtsRpcApi::handle_ots_has_code(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        const auto error_msg = "invalid ots_hasCode params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto address = params[0].get<evmc::address>();
    const auto block_id = params[1].get<std::string>();

    SILKRPC_DEBUG << "address: " << silkworm::to_hex(address) << " block_id: " << block_id << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        ethdb::kv::CachedDatabase cached_database{BlockNumberOrHash{block_id}, *tx, *state_cache_};
        // Check if target block is latest one: use local state cache (if any) for target transaction
        const bool is_latest_block = co_await core::is_latest_block_number(BlockNumberOrHash{block_id}, tx_database);
        StateReader state_reader{is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database)};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        std::optional<silkworm::Account> account{co_await state_reader.read_account(address, block_number + 1)};

        if (account) {
            auto code{co_await state_reader.read_code(account->code_hash)};
            reply = make_json_content(request["id"], code.has_value());
        } else {
            reply = make_json_content(request["id"], false);
        }
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

boost::asio::awaitable<void> OtsRpcApi::handle_ots_getBlockDetails(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid handle_ots_getBlockDetails params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();

    SILKRPC_DEBUG << "block_id: " << block_id << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        const auto block_hash = co_await core::rawdb::read_canonical_block_hash(tx_database, block_number);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_hash, block_number);
        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);

        const Block extended_block{block_with_hash, total_difficulty, false};
        auto block_size = extended_block.get_block_size();

        const BlockDetails block_details{block_size, block_hash, block_with_hash.block.header, total_difficulty, block_with_hash.block.transactions.size(), block_with_hash.block.ommers};

        auto receipts = co_await core::get_receipts(tx_database, block_with_hash);
        auto chain_config = co_await core::rawdb::read_chain_config(tx_database);

        IssuanceDetails issuance = get_issuance(chain_config, block_with_hash);
        intx::uint256 total_fees = get_block_fees(chain_config, block_with_hash, receipts, block_number);

        const BlockDetailsResponse block_details_response{block_details, issuance, total_fees};

        reply = make_json_content(request["id"], block_details_response);
    } catch (const std::invalid_argument& iv) {
        SILKRPC_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

boost::asio::awaitable<void> OtsRpcApi::handle_ots_getBlockDetailsByHash(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid ots_getBlockDetailsByHash params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto block_hash = params[0].get<evmc::bytes32>();

    SILKRPC_DEBUG << "block_hash: " << block_hash << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await read_header_number(tx_database, block_hash);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_hash, block_number);
        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);

        const Block extended_block{block_with_hash, total_difficulty, false};
        auto block_size = extended_block.get_block_size();

        const BlockDetails block_details{block_size, block_hash, block_with_hash.block.header, total_difficulty, block_with_hash.block.transactions.size() - 2, block_with_hash.block.ommers};

        auto receipts = co_await core::get_receipts(tx_database, block_with_hash);
        auto chain_config = co_await core::rawdb::read_chain_config(tx_database);

        IssuanceDetails issuance = get_issuance(chain_config, block_with_hash);
        intx::uint256 total_fees = get_block_fees(chain_config, block_with_hash, receipts, block_number);

        const BlockDetailsResponse block_details_response{block_details, issuance, total_fees};

        reply = make_json_content(request["id"], block_details_response);
    } catch (const std::invalid_argument& iv) {
        SILKRPC_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_content(request["id"], {});
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

boost::asio::awaitable<void> OtsRpcApi::handle_ots_getBlockTransactions(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        auto error_msg = "invalid ots_getBlockTransactions params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    const auto block_id = params[0].get<std::string>();
    const auto page_number = params[1].get<std::size_t>();
    const auto page_size = params[2].get<std::size_t>();

    SILKRPC_DEBUG << "block_id: " << block_id << " page_number: " << page_number << " page_size: " << page_size << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_with_hash.hash, block_number);
        auto receipts = co_await core::get_receipts(tx_database, block_with_hash);

        const Block extended_block{block_with_hash, total_difficulty, false};
        auto block_size = extended_block.get_block_size();

        auto transaction_count = block_with_hash.block.transactions.size();

        BlockTransactionsResponse block_transactions{block_size, block_with_hash.hash, block_with_hash.block.header, total_difficulty, transaction_count, block_with_hash.block.ommers};

        auto page_end = block_with_hash.block.transactions.size() - (page_size * page_number);

        if (page_end > block_with_hash.block.transactions.size()) {
            page_end = 0;
        }

        auto page_start = page_end - page_size;

        if (page_start > page_end) {
            page_start = 0;
        }

        for (auto i = page_start; i < page_end; i++) {
            block_transactions.receipts.push_back(receipts.at(i));
            block_transactions.transactions.push_back(block_with_hash.block.transactions.at(i));
        }

        reply = make_json_content(request["id"], block_transactions);

    } catch (const std::invalid_argument& iv) {
        SILKRPC_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_content(request["id"], {});
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

IssuanceDetails OtsRpcApi::get_issuance(const ChainConfig& chain_config, const silkworm::BlockWithHash& block) {
    auto config = silkworm::ChainConfig::from_json(chain_config.config).value();

    if (config.seal_engine != silkworm::SealEngineType::kEthash) {
        return IssuanceDetails{};
    }

    auto block_reward = ethash::compute_reward(chain_config, block.block);

    intx::uint256 ommers_reward = std::accumulate(block_reward.ommer_rewards.begin(), block_reward.ommer_rewards.end(), intx::uint256{0});

    IssuanceDetails issuance{
        .miner_reward = block_reward.miner_reward,
        .ommers_reward = ommers_reward,
        .total_reward = block_reward.miner_reward + ommers_reward};

    return issuance;
}

intx::uint256 OtsRpcApi::get_block_fees(const ChainConfig& chain_config, const silkworm::BlockWithHash& block, std::vector<Receipt>& receipts, silkworm::BlockNum block_number) {
    auto config = silkworm::ChainConfig::from_json(chain_config.config).value();

    intx::uint256 fees = 0;
    for (const auto& receipt : receipts) {
        auto txn = block.block.transactions[receipt.tx_index];

        intx::uint256 effective_gas_price;
        if (config.london_block && block_number >= config.london_block.value()) {
            intx::uint256 base_fee = block.block.header.base_fee_per_gas.value_or(0);
            intx::uint256 gas_price = txn.effective_gas_price(base_fee);
            effective_gas_price = base_fee + gas_price;

        } else {
            intx::uint256 base_fee = block.block.header.base_fee_per_gas.value_or(0);
            effective_gas_price = txn.effective_gas_price(base_fee);
        }

        fees += effective_gas_price * receipt.gas_used;
    }
    return fees;
}

}  // namespace silkworm::rpc::commands
