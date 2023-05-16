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

#include "erigon_api.hpp"

#include <string>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/protocol/ethash_rule_set.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/common/binary_search.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/core/receipts.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#erigon_getBlockByTimestamp
awaitable<void> ErigonRpcApi::handle_erigon_get_block_by_timestamp(const nlohmann::json& request, nlohmann::json& reply) {
    // Decode request parameters
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid erigon_getBlockByTimestamp params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_timestamp = params[0].get<std::string>();
    const auto full_tx = params[1].get<bool>();
    SILK_DEBUG << "block_timestamp: " << block_timestamp << " full_tx: " << full_tx;

    const std::string::size_type begin = block_timestamp.find_first_not_of(" \"");
    const std::string::size_type end = block_timestamp.find_last_not_of(" \"");
    const auto timestamp = static_cast<uint64_t>(std::stol(block_timestamp.substr(begin, end - begin + 1), nullptr, 0));

    // Open a new remote database transaction (no need to close if code throws before the end)
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        // Lookup the first and last block headers
        const auto first_header = co_await core::rawdb::read_header_by_number(tx_database, core::kEarliestBlockNumber);
        const auto current_header = co_await core::rawdb::read_current_header(tx_database);
        const uint64_t current_block_number = current_header.number;

        // Find the lowest block header w/ timestamp greater or equal to provided timestamp
        uint64_t block_number;
        if (current_header.timestamp <= timestamp) {
            block_number = current_block_number;
        } else if (first_header.timestamp >= timestamp) {
            block_number = core::kEarliestBlockNumber;
        } else {
            // Good-old binary search to find the lowest block header matching timestamp
            const auto matching_block_number = co_await binary_search(current_block_number, [&](uint64_t i) -> awaitable<bool> {
                const auto header = co_await core::rawdb::read_header_by_number(tx_database, i);
                co_return header.timestamp >= timestamp;
            });
            // TODO(canepat) we should try to avoid this block header lookup (just done in search)
            const auto matching_header = co_await core::rawdb::read_header_by_number(tx_database, matching_block_number);
            if (matching_header.timestamp > timestamp) {
                block_number = matching_block_number - 1;
            } else {
                block_number = matching_block_number;
            }
        }

        // Lookup and return the matching block
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_with_hash->hash, block_number);
        const Block extended_block{*block_with_hash, total_difficulty, full_tx};

        reply = make_json_content(request["id"], extended_block);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    // Close remote database transaction, RAII not available with coroutines
    co_await tx->close();
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getHeaderByHash
awaitable<void> ErigonRpcApi::handle_erigon_get_header_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_getHeaderByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "block_hash: " << block_hash;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto header{co_await core::rawdb::read_header_by_hash(tx_database, block_hash)};

        reply = make_json_content(request["id"], header);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getHeaderByNumber
awaitable<void> ErigonRpcApi::handle_erigon_get_header_by_number(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_getHeaderByNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id;

    if (block_id == core::kPendingBlockId) {
        // TODO(canepat): add pending block only known to the miner
        auto error_msg = "pending block not implemented in erigon_getHeaderByNumber";
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        const auto header{co_await core::rawdb::read_header_by_number(tx_database, block_number)};

        reply = make_json_content(request["id"], header);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getlogsbyhash
awaitable<void> ErigonRpcApi::handle_erigon_get_logs_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_getLogsByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "block_hash: " << block_hash;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);
        const auto receipts{co_await core::get_receipts(tx_database, *block_with_hash)};

        SILK_DEBUG << "receipts.size(): " << receipts.size();
        std::vector<Logs> logs{};
        logs.reserve(receipts.size());
        for (const auto& receipt : receipts) {
            SILK_DEBUG << "receipt.logs.size(): " << receipt.logs.size();
            logs.push_back(receipt.logs);
        }
        SILK_DEBUG << "logs.size(): " << logs.size();

        reply = make_json_content(request["id"], logs);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_forks
awaitable<void> ErigonRpcApi::handle_erigon_forks(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto chain_config{co_await core::rawdb::read_chain_config(tx_database)};
        SILK_DEBUG << "chain config: " << chain_config;

        Forks forks{chain_config};

        reply = make_json_content(request["id"], forks);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_WatchTheBurn
awaitable<void> ErigonRpcApi::handle_erigon_watch_the_burn(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_watchTheBurn params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto chain_config{co_await core::rawdb::read_chain_config(tx_database)};
        SILK_DEBUG << "chain config: " << chain_config;

        Issuance issuance{};  // default is empty: no PoW => no issuance
        if (chain_config.config.count("ethash") != 0) {
            const auto block_number = co_await core::get_block_number(block_id, tx_database);
            const auto block_with_hash{co_await core::read_block_by_number(*block_cache_, tx_database, block_number)};
            const auto cc{silkworm::ChainConfig::from_json(chain_config.config)};
            if (!cc) {
                throw std::runtime_error("Invalid chain config");
            }
            const auto block_reward{protocol::EthashRuleSet::compute_reward(*cc, block_with_hash->block)};
            intx::uint256 total_ommer_reward = 0;
            for (const auto ommer_reward : block_reward.ommers) {
                total_ommer_reward += ommer_reward;
            }
            intx::uint256 block_issuance = block_reward.miner + total_ommer_reward;
            issuance.block_reward = "0x" + intx::hex(block_reward.miner);
            issuance.ommer_reward = "0x" + intx::hex(total_ommer_reward);
            issuance.issuance = "0x" + intx::hex(block_issuance);
            intx::uint256 burnt;
            if (block_with_hash->block.header.base_fee_per_gas) {
                burnt = *block_with_hash->block.header.base_fee_per_gas * block_with_hash->block.header.gas_used;
            } else {
                burnt = 0;
            }
            issuance.burnt = "0x" + intx::hex(burnt);

            const auto total_issued = co_await core::rawdb::read_total_issued(tx_database, block_number);
            const auto total_burnt = co_await core::rawdb::read_total_burnt(tx_database, block_number);

            issuance.total_issued = "0x" + intx::hex(total_issued);
            issuance.total_burnt = "0x" + intx::hex(total_burnt);
            intx::uint256 tips = 0;
            if (block_with_hash->block.header.base_fee_per_gas) {
                const auto receipts{co_await core::get_receipts(tx_database, *block_with_hash)};
                const auto block{block_with_hash->block};
                for (size_t i{0}; i < block.transactions.size(); i++) {
                    auto tip = block.transactions[i].effective_gas_price(block.header.base_fee_per_gas.value_or(0));
                    tips += tip * receipts[i].gas_used;
                }
            }
            issuance.tips = "0x" + intx::hex(tips);
        }
        reply = make_json_content(request["id"], issuance);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_blockNumber
awaitable<void> ErigonRpcApi::handle_erigon_block_number(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    std::string block_id;
    if (params.empty()) {
        block_id = core::kLatestExecutedBlockId;
    } else if (params.size() == 1) {
        block_id = params[0];
    } else {
        auto error_msg = "invalid erigon_blockNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    SILK_DEBUG << "block: " << block_id;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto block_number{co_await core::get_block_number_by_tag(block_id, tx_database)};
        reply = make_json_content(request["id"], to_quantity(block_number));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_cumulativeChainTraffic
awaitable<void> ErigonRpcApi::handle_erigon_cumulative_chain_traffic(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_cumulativeChainTraffic params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();

    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin();

    ChainTraffic chain_traffic;

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        chain_traffic.cumulative_transactions_count = co_await core::rawdb::read_cumulative_transaction_count(tx_database, block_number);
        chain_traffic.cumulative_gas_used = co_await core::rawdb::read_cumulative_gas_used(tx_database, block_number);

        reply = make_json_content(request["id"], chain_traffic);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_content(request["id"], chain_traffic);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_nodeInfo
awaitable<void> ErigonRpcApi::handle_erigon_node_info(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto node_info_data = co_await backend_->engine_node_info();

        reply = make_json_content(request["id"], node_info_data);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_return;
}

}  // namespace silkworm::rpc::commands
