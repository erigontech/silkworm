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

#include "eth_api.hpp"

#include <algorithm>
#include <cstring>
#include <exception>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <utility>

#include <boost/endian/conversion.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/db/util.hpp>
#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/estimate_gas_oracle.hpp>
#include <silkworm/silkrpc/core/evm_access_list_tracer.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/core/gas_price_oracle.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/core/receipts.hpp>
#include <silkworm/silkrpc/core/remote_state.hpp>
#include <silkworm/silkrpc/core/state_reader.hpp>
#include <silkworm/silkrpc/ethdb/bitmap.hpp>
#include <silkworm/silkrpc/ethdb/cbor.hpp>
#include <silkworm/silkrpc/ethdb/kv/cached_database.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/stagedsync/stages.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/filter.hpp>
#include <silkworm/silkrpc/types/syncing_data.hpp>
#include <silkworm/silkrpc/types/transaction.hpp>

namespace silkworm::rpc::commands {

awaitable<std::pair<uint64_t, uint64_t>> get_block_numbers(const Filter& filter, const core::rawdb::DatabaseReader& reader) {
    uint64_t start{}, end{};
    if (filter.block_hash.has_value()) {
        auto block_hash_bytes = silkworm::from_hex(filter.block_hash.value());
        if (!block_hash_bytes.has_value()) {
            start = end = std::numeric_limits<uint64_t>::max();
        } else {
            auto block_hash = silkworm::to_bytes32(block_hash_bytes.value());
            auto block_number = co_await core::rawdb::read_header_number(reader, block_hash);
            start = end = block_number;
        }
    } else {
        uint64_t last_executed_block_number = std::numeric_limits<uint64_t>::max();
        if (filter.from_block.has_value()) {
            start = co_await core::get_block_number(filter.from_block.value(), reader);
        } else {
            last_executed_block_number = co_await core::get_latest_executed_block_number(reader);
            start = last_executed_block_number;
        }
        if (filter.to_block.has_value()) {
            end = co_await core::get_block_number(filter.to_block.value(), reader);
        } else {
            if (last_executed_block_number == std::numeric_limits<uint64_t>::max()) {
                last_executed_block_number = co_await core::get_latest_executed_block_number(reader);
            }
            end = last_executed_block_number;
        }
    }
    co_return std::make_pair(start, end);
}

// https://eth.wiki/json-rpc/API#eth_blocknumber
awaitable<void> EthereumRpcApi::handle_eth_block_number(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto block_height = co_await core::get_latest_block_number(tx_database);
        reply = make_json_content(request["id"], to_quantity(block_height));
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

// https://eth.wiki/json-rpc/API#eth_chainid
awaitable<void> EthereumRpcApi::handle_eth_chain_id(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_id = co_await core::rawdb::read_chain_id(tx_database);
        reply = make_json_content(request["id"], to_quantity(chain_id));
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

// https://eth.wiki/json-rpc/API#eth_protocolversion
awaitable<void> EthereumRpcApi::handle_eth_protocol_version(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto protocol_version = co_await backend_->protocol_version();
        reply = make_json_content(request["id"], to_quantity(protocol_version));
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_return;
}

// https://eth.wiki/json-rpc/API#eth_syncing
awaitable<void> EthereumRpcApi::handle_eth_syncing(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto current_block_height = co_await core::get_current_block_number(tx_database);
        const auto highest_block_height = co_await core::get_highest_block_number(tx_database);
        if (current_block_height >= highest_block_height) {
            reply = make_json_content(request["id"], false);
        } else {
            SyncingData syncing_data{};

            syncing_data.current_block = to_quantity(current_block_height);
            syncing_data.highest_block = to_quantity(highest_block_height);
            for (std::size_t i{0}; i < sizeof(silkworm::db::stages::kAllStages) / sizeof(char*) - 1; i++) {  // no unWind
                StageData current_stage;
                current_stage.stage_name = silkworm::db::stages::kAllStages[i];
                current_stage.block_number = to_quantity(co_await stages::get_sync_stage_progress(tx_database, silkworm::bytes_of_string(current_stage.stage_name)));
                syncing_data.stages.push_back(current_stage);
            }
            reply = make_json_content(request["id"], syncing_data);
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

// https://eth.wiki/json-rpc/API#eth_gasprice
awaitable<void> EthereumRpcApi::handle_eth_gas_price(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto latest_block_number = co_await core::get_block_number(core::kLatestBlockId, tx_database);
        SILKRPC_INFO << "latest_block_number " << latest_block_number << "\n";

        BlockProvider block_provider = [this, &tx_database](uint64_t block_number) {
            return core::read_block_by_number(*block_cache_, tx_database, block_number);
        };

        GasPriceOracle gas_price_oracle{block_provider};
        auto gas_price = co_await gas_price_oracle.suggested_price(latest_block_number);

        const auto block_with_hash = co_await block_provider(latest_block_number);
        const auto base_fee = block_with_hash.block.header.base_fee_per_gas.value_or(0);
        gas_price += base_fee;
        reply = make_json_content(request["id"], to_quantity(gas_price));
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

// https://eth.wiki/json-rpc/API#eth_getblockbyhash
awaitable<void> EthereumRpcApi::handle_eth_get_block_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getBlockByHash params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto block_hash = params[0].get<evmc::bytes32>();
    auto full_tx = params[1].get<bool>();
    SILKRPC_DEBUG << "block_hash: " << block_hash << " full_tx: " << std::boolalpha << full_tx << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);
        const auto block_number = block_with_hash.block.header.number;
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_hash, block_number);
        const Block extended_block{block_with_hash, total_difficulty, full_tx};

        reply = make_json_content(request["id"], extended_block);
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

// https://eth.wiki/json-rpc/API#eth_getblockbynumber
awaitable<void> EthereumRpcApi::handle_eth_get_block_by_number(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid getBlockByNumber params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    auto full_tx = params[1].get<bool>();
    SILKRPC_DEBUG << "block_id: " << block_id << " full_tx: " << std::boolalpha << full_tx << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_with_hash.hash, block_number);
        const Block extended_block{block_with_hash, total_difficulty, full_tx};

        reply = make_json_content(request["id"], extended_block);
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

// https://eth.wiki/json-rpc/API#eth_getblocktransactioncountbyhash
awaitable<void> EthereumRpcApi::handle_eth_get_block_transaction_count_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getBlockTransactionCountByHash params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto block_hash = params[0].get<evmc::bytes32>();
    SILKRPC_DEBUG << "block_hash: " << block_hash << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);
        const auto tx_count = block_with_hash.block.transactions.size();

        reply = make_json_content(request["id"], to_quantity(tx_count));
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

// https://eth.wiki/json-rpc/API#eth_getblocktransactioncountbynumber
awaitable<void> EthereumRpcApi::handle_eth_get_block_transaction_count_by_number(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getBlockTransactionCountByNumber params: " + params.dump();
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
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);

        reply = make_json_content(request["id"], to_quantity(block_with_hash.block.transactions.size()));
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

// https://eth.wiki/json-rpc/API#eth_getunclebyblockhashandindex
awaitable<void> EthereumRpcApi::handle_eth_get_uncle_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getUncleByBlockHashAndIndex params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    const auto index = params[1].get<std::string>();
    SILKRPC_DEBUG << "block_hash: " << block_hash << " index: " << index << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);
        const auto ommers = block_with_hash.block.ommers;

        const auto idx = std::stoul(index, nullptr, 16);
        if (idx >= ommers.size()) {
            SILKRPC_WARN << "invalid_argument: index not found processing request: " << request.dump() << "\n";
            reply = make_json_content(request["id"], nullptr);
        } else {
            const auto block_number = block_with_hash.block.header.number;
            const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_hash, block_number);
            auto uncle = ommers[idx];

            silkworm::BlockWithHash uncle_block_with_hash{{{}, uncle}, uncle.hash()};
            const Block uncle_block_with_hash_and_td{uncle_block_with_hash, total_difficulty};

            reply = make_json_content(request["id"], uncle_block_with_hash_and_td);
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

// https://eth.wiki/json-rpc/API#eth_getunclebyblocknumberandindex
awaitable<void> EthereumRpcApi::handle_eth_get_uncle_by_block_number_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getUncleByBlockNumberAndIndex params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    const auto index = params[1].get<std::string>();
    SILKRPC_DEBUG << "block_id: " << block_id << " index: " << index << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        const auto ommers = block_with_hash.block.ommers;

        const auto idx = std::stoul(index, nullptr, 16);
        if (idx >= ommers.size()) {
            SILKRPC_WARN << "invalid_argument: index not found processing request: " << request.dump() << "\n";
            reply = make_json_content(request["id"], nullptr);
        } else {
            const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_with_hash.hash, block_number);
            auto uncle = ommers[idx];

            silkworm::BlockWithHash uncle_block_with_hash{{{}, uncle}, uncle.hash()};
            const Block uncle_block_with_hash_and_td{uncle_block_with_hash, total_difficulty};

            reply = make_json_content(request["id"], uncle_block_with_hash_and_td);
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

// https://eth.wiki/json-rpc/API#eth_getunclecountbyblockhash
awaitable<void> EthereumRpcApi::handle_eth_get_uncle_count_by_block_hash(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getUncleCountByBlockHash params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto block_hash = params[0].get<evmc::bytes32>();
    SILKRPC_DEBUG << "block_hash: " << block_hash << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);
        const auto ommers = block_with_hash.block.ommers;

        reply = make_json_content(request["id"], to_quantity(ommers.size()));
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

// https://eth.wiki/json-rpc/API#eth_getunclecountbyblocknumber
awaitable<void> EthereumRpcApi::handle_eth_get_uncle_count_by_block_number(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getUncleCountByBlockNumber params: " + params.dump();
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
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        const auto ommers = block_with_hash.block.ommers;

        reply = make_json_content(request["id"], to_quantity(ommers.size()));
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

// https://eth.wiki/json-rpc/API#eth_gettransactionbyhash
awaitable<void> EthereumRpcApi::handle_eth_get_transaction_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getTransactionByHash params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto transaction_hash = params[0].get<evmc::bytes32>();
    SILKRPC_DEBUG << "transaction_hash: " << transaction_hash << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto tx_with_block = co_await core::read_transaction_by_hash(*block_cache_, tx_database, transaction_hash);
        if (!tx_with_block) {
            const auto tx_rlp_buffer = co_await tx_pool_->get_transaction(transaction_hash);
            if (tx_rlp_buffer) {
                silkworm::ByteView encoded_tx_view{*tx_rlp_buffer};
                Transaction transaction;
                const auto decoding_result = silkworm::rlp::decode<silkworm::Transaction>(encoded_tx_view, transaction);
                if (decoding_result) {
                    transaction.queued_in_pool = true;
                    reply = make_json_content(request["id"], transaction);
                } else {
                    const auto error_msg = "invalid RLP decoding for tx hash: " + silkworm::to_hex(transaction_hash);
                    SILKRPC_ERROR << error_msg << "\n";
                    reply = make_json_error(request["id"], 100, error_msg);
                }
            } else {
                const auto error_msg = "tx hash: " + silkworm::to_hex(transaction_hash) + " does not exist in pool";
                SILKRPC_ERROR << error_msg << "\n";
                reply = make_json_error(request["id"], 100, error_msg);
            }
        } else {
            reply = make_json_content(request["id"], tx_with_block->transaction);
        }
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

// https://eth.wiki/json-rpc/API#eth_getrawtransactionbyhash
awaitable<void> EthereumRpcApi::handle_eth_get_raw_transaction_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getRawTransactionByHash params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto transaction_hash = params[0].get<evmc::bytes32>();
    SILKRPC_DEBUG << "transaction_hash: " << transaction_hash << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto tx_with_block = co_await core::read_transaction_by_hash(*block_cache_, tx_database, transaction_hash);
        if (!tx_with_block) {
            const auto tx_rlp_buffer = co_await tx_pool_->get_transaction(transaction_hash);
            if (tx_rlp_buffer) {
                Rlp rlp{*tx_rlp_buffer};
                reply = make_json_content(request["id"], rlp);
            } else {
                const auto error_msg = "tx hash: " + silkworm::to_hex(transaction_hash) + " does not exist in pool";
                SILKRPC_ERROR << error_msg << "\n";
                reply = make_json_error(request["id"], 100, error_msg);
            }
        } else {
            Rlp rlp{};
            silkworm::rlp::encode(rlp.buffer, tx_with_block->transaction, false, false);
            reply = make_json_content(request["id"], rlp);
        }
    } catch (const std::invalid_argument& iv) {
        Rlp rlp{};
        reply = make_json_content(request["id"], rlp);
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

// https://eth.wiki/json-rpc/API#eth_gettransactionbyblockhashandindex
awaitable<void> EthereumRpcApi::handle_eth_get_transaction_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getTransactionByBlockHashAndIndex params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    const auto index = params[1].get<std::string>();
    SILKRPC_DEBUG << "block_hash: " << block_hash << " index: " << index << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);
        const auto transactions = block_with_hash.block.transactions;

        const auto idx = std::stoul(index, nullptr, 16);
        if (idx >= transactions.size()) {
            SILKRPC_WARN << "Transaction not found for index: " << index << "\n";
            reply = make_json_content(request["id"], nullptr);
        } else {
            const auto block_header = block_with_hash.block.header;
            rpc::Transaction txn{transactions[idx], block_with_hash.hash, block_header.number, block_header.base_fee_per_gas, idx};
            reply = make_json_content(request["id"], txn);
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

// https://eth.wiki/json-rpc/API#eth_getrawtransactionbyblockhashandindex
awaitable<void> EthereumRpcApi::handle_eth_get_raw_transaction_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getRawTransactionByBlockHashAndIndex params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    const auto index = params[1].get<std::string>();
    SILKRPC_DEBUG << "block_hash: " << block_hash << " index: " << index << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);
        const auto transactions = block_with_hash.block.transactions;

        const auto idx = std::stoul(index, nullptr, 16);
        if (idx >= transactions.size()) {
            SILKRPC_WARN << "Transaction not found for index: " << index << "\n";
            Rlp rlp{};
            reply = make_json_content(request["id"], rlp);
        } else {
            Rlp rlp{};
            silkworm::rlp::encode(rlp.buffer, transactions[idx], false, false);
            reply = make_json_content(request["id"], rlp);
        }
    } catch (const std::invalid_argument& iv) {
        Rlp rlp{};
        reply = make_json_content(request["id"], rlp);
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

// https://eth.wiki/json-rpc/API#eth_gettransactionbyblocknumberandindex
awaitable<void> EthereumRpcApi::handle_eth_get_transaction_by_block_number_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getTransactionByBlockNumberAndIndex params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    const auto index = params[1].get<std::string>();
    SILKRPC_DEBUG << "block_id: " << block_id << " index: " << index << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        const auto transactions = block_with_hash.block.transactions;

        const auto idx = std::stoul(index, nullptr, 16);
        if (idx >= transactions.size()) {
            SILKRPC_WARN << "Transaction not found for index: " << index << "\n";
            reply = make_json_content(request["id"], nullptr);
        } else {
            const auto block_header = block_with_hash.block.header;
            rpc::Transaction txn{transactions[idx], block_with_hash.hash, block_header.number, block_header.base_fee_per_gas, idx};
            reply = make_json_content(request["id"], txn);
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

// https://eth.wiki/json-rpc/API#eth_getrawtransactionbyblocknumberandindex
awaitable<void> EthereumRpcApi::handle_eth_get_raw_transaction_by_block_number_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getRawTransactionByBlockNumberAndIndex params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    const auto index = params[1].get<std::string>();
    SILKRPC_DEBUG << "block_id: " << block_id << " index: " << index << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        const auto transactions = block_with_hash.block.transactions;

        const auto idx = std::stoul(index, nullptr, 16);
        if (idx >= transactions.size()) {
            SILKRPC_WARN << "Transaction not found for index: " << index << "\n";
            Rlp rlp{};
            reply = make_json_content(request["id"], rlp);
        } else {
            Rlp rlp{};
            silkworm::rlp::encode(rlp.buffer, transactions[idx], false, false);
            reply = make_json_content(request["id"], rlp);
        }
    } catch (const std::invalid_argument& iv) {
        Rlp rlp{};
        reply = make_json_content(request["id"], rlp);
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

// https://eth.wiki/json-rpc/API#eth_gettransactionreceipt
awaitable<void> EthereumRpcApi::handle_eth_get_transaction_receipt(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getTransactionReceipt params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto transaction_hash = params[0].get<evmc::bytes32>();
    SILKRPC_DEBUG << "transaction_hash: " << transaction_hash << "\n";
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_transaction_hash(*block_cache_, tx_database, transaction_hash);
        auto receipts = co_await core::get_receipts(tx_database, block_with_hash);
        auto transactions = block_with_hash.block.transactions;
        if (receipts.size() != transactions.size()) {
            throw std::invalid_argument{"Unexpected size for receipts in handle_eth_get_transaction_receipt"};
        }

        std::optional<std::size_t> tx_index;
        for (size_t idx{0}; idx < transactions.size(); idx++) {
            auto ethash_hash{hash_of_transaction(transactions[idx])};

            SILKRPC_TRACE << "tx " << idx << ") hash: " << silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength}) << "\n";
            if (std::memcmp(transaction_hash.bytes, ethash_hash.bytes, silkworm::kHashLength) == 0) {
                tx_index = idx;
                const intx::uint256 base_fee_per_gas{block_with_hash.block.header.base_fee_per_gas.value_or(0)};
                const intx::uint256 effective_gas_price{transactions[idx].max_fee_per_gas >= base_fee_per_gas ? transactions[idx].effective_gas_price(base_fee_per_gas)
                                                                                                              : transactions[idx].max_priority_fee_per_gas};
                receipts[idx].effective_gas_price = effective_gas_price;
                break;
            }
        }
        if (!tx_index) {
            throw std::invalid_argument{"Unexpected transaction index in handle_eth_get_transaction_receipt"};
        }
        reply = make_json_content(request["id"], receipts[*tx_index]);
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

// https://eth.wiki/json-rpc/API#eth_estimategas
awaitable<void> EthereumRpcApi::handle_eth_estimate_gas(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_estimategas params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto call = params[0].get<Call>();
    SILKRPC_DEBUG << "call: " << call << "\n";

    auto tx = co_await database_->begin();

    try {
        const BlockNumberOrHash block_number_or_hash{core::kLatestBlockId};
        ethdb::kv::CachedDatabase cached_database{block_number_or_hash, *tx, *state_cache_};
        ethdb::TransactionDatabase tx_database{*tx};

        const auto chain_id = co_await core::rawdb::read_chain_id(tx_database);
        const auto chain_config_ptr = lookup_chain_config(chain_id);
        const auto latest_block_number = co_await core::get_block_number(core::kLatestBlockId, tx_database);
        SILKRPC_DEBUG << "chain_id: " << chain_id << ", latest_block_number: " << latest_block_number << "\n";

        const auto latest_block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, latest_block_number);
        const auto latest_block = latest_block_with_hash.block;
        StateReader state_reader(cached_database);
        state::RemoteState remote_state{*context_.io_context(), cached_database, latest_block.header.number};

        Tracers tracers;
        EVMExecutor evm_executor{*chain_config_ptr, workers_, remote_state};

        rpc::Executor executor = [&latest_block, &evm_executor, &tracers](const silkworm::Transaction& transaction) {
            return evm_executor.call(latest_block, transaction, tracers);
        };

        rpc::BlockHeaderProvider block_header_provider = [&cached_database](uint64_t block_number) {
            return core::rawdb::read_header_by_number(cached_database, block_number);
        };

        rpc::AccountReader account_reader = [&state_reader](const evmc::address& address, uint64_t block_number) {
            return state_reader.read_account(address, block_number + 1);
        };

        rpc::EstimateGasOracle estimate_gas_oracle{block_header_provider, account_reader, executor};

        auto estimated_gas = co_await estimate_gas_oracle.estimate_gas(call, latest_block_number);

        reply = make_json_content(request["id"], to_quantity(estimated_gas));
    } catch (const rpc::EstimateGasException& e) {
        SILKRPC_ERROR << "EstimateGasException: code: " << e.error_code() << " message: " << e.message() << " processing request: " << request.dump() << "\n";
        if (e.data().empty()) {
            reply = make_json_error(request["id"], e.error_code(), e.message());
        } else {
            reply = make_json_error(request["id"], RevertError{{3, e.message()}, e.data()});
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

// https://eth.wiki/json-rpc/API#eth_getbalance
awaitable<void> EthereumRpcApi::handle_eth_get_balance(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getBalance params: " + params.dump();
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
        const auto [block_number, is_latest_block] = co_await core::get_block_number(block_id, tx_database, /*latest_required=*/true);

        StateReader state_reader{
            is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database)};
        std::optional<silkworm::Account> account{co_await state_reader.read_account(address, block_number + 1)};

        reply = make_json_content(request["id"], "0x" + (account ? intx::hex(account->balance) : "0"));
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

// https://eth.wiki/json-rpc/API#eth_getcode
awaitable<void> EthereumRpcApi::handle_eth_get_code(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getCode params: " + params.dump();
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
        const auto [block_number, is_latest_block] = co_await core::get_block_number(block_id, tx_database, /*latest_required=*/true);
        StateReader state_reader{
            is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database)};

        std::optional<silkworm::Account> account{co_await state_reader.read_account(address, block_number + 1)};

        if (account) {
            auto code{co_await state_reader.read_code(account->code_hash)};
            reply = make_json_content(request["id"], code ? ("0x" + silkworm::to_hex(*code)) : "0x");
        } else {
            reply = make_json_content(request["id"], "0x");
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

// https://eth.wiki/json-rpc/API#eth_gettransactioncount
awaitable<void> EthereumRpcApi::handle_eth_get_transaction_count(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getTransactionCount params: " + params.dump();
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
        const auto [block_number, is_latest_block] = co_await core::get_block_number(block_id, tx_database, /*latest_required=*/true);
        StateReader state_reader{
            is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database)};

        std::optional<silkworm::Account> account{co_await state_reader.read_account(address, block_number + 1)};

        if (account) {
            reply = make_json_content(request["id"], to_quantity(account->nonce));
        } else {
            reply = make_json_content(request["id"], "0x0");
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

// https://eth.wiki/json-rpc/API#eth_getstorageat
awaitable<void> EthereumRpcApi::handle_eth_get_storage_at(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 3) {
        auto error_msg = "invalid eth_getStorageAt params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto address = params[0].get<evmc::address>();
    const auto location = params[1].get<evmc::bytes32>();
    const auto block_id = params[2].get<std::string>();
    SILKRPC_DEBUG << "address: " << silkworm::to_hex(address) << " block_id: " << block_id << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        ethdb::kv::CachedDatabase cached_database{BlockNumberOrHash{block_id}, *tx, *state_cache_};
        const auto [block_number, is_latest_block] = co_await core::get_block_number(block_id, tx_database, /*latest_required=*/true);
        StateReader state_reader{
            is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database)};
        std::optional<silkworm::Account> account{co_await state_reader.read_account(address, block_number + 1)};

        if (account) {
            auto storage{co_await state_reader.read_storage(address, account->incarnation, location, block_number + 1)};
            reply = make_json_content(request["id"], "0x" + silkworm::to_hex(storage));
        } else {
            reply = make_json_content(request["id"], "0x0000000000000000000000000000000000000000000000000000000000000000");
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

// https://eth.wiki/json-rpc/API#eth_call
awaitable<void> EthereumRpcApi::handle_eth_call(const nlohmann::json& request, std::string& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILKRPC_ERROR << error_msg << request.dump() << "\n";
        make_glaze_json_error(reply, request["id"], -32602, error_msg);
        co_return;
    }
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_call params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        make_glaze_json_error(reply, request["id"], -32602, error_msg);
        co_return;
    }
    const auto call = params[0].get<Call>();
    const auto block_id = params[1].get<std::string>();
    SILKRPC_DEBUG << "call: " << call << " block_id: " << block_id << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        ethdb::kv::CachedDatabase cached_database{BlockNumberOrHash{block_id}, *tx, *state_cache_};

        const auto chain_id = co_await core::rawdb::read_chain_id(tx_database);
        const auto chain_config_ptr = lookup_chain_config(chain_id);
        const auto [block_number, is_latest_block] = co_await core::get_block_number(block_id, tx_database, /*latest_required=*/true);

        state::RemoteState remote_state{*context_.io_context(),
                                        is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database),
                                        block_number};
        EVMExecutor executor{*chain_config_ptr, workers_, remote_state};
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        silkworm::Transaction txn{call.to_transaction()};
        const auto execution_result = co_await executor.call(block_with_hash.block, txn);

        if (execution_result.pre_check_error) {
            make_glaze_json_error(reply, request["id"], -32000, execution_result.pre_check_error.value());
        } else if (execution_result.error_code == evmc_status_code::EVMC_SUCCESS) {
            make_glaze_json_content(reply, request["id"], execution_result.data);
        } else {
            const auto error_message = EVMExecutor::get_error_message(execution_result.error_code, execution_result.data);
            if (execution_result.data.empty()) {
                make_glaze_json_error(reply, request["id"], -32000, error_message);
            } else {
                make_glaze_json_error(reply, request["id"], RevertError{{3, error_message}, execution_result.data});
            }
        }
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        make_glaze_json_error(reply, request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        make_glaze_json_error(reply, request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#eth_call
boost::asio::awaitable<void> EthereumRpcApi::handle_eth_call_original(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_call params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto call = params[0].get<Call>();
    const auto block_id = params[1].get<std::string>();
    SILKRPC_DEBUG << "call: " << call << " block_id: " << block_id << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        ethdb::kv::CachedDatabase cached_database{BlockNumberOrHash{block_id}, *tx, *state_cache_};

        const auto chain_id = co_await core::rawdb::read_chain_id(tx_database);
        const auto chain_config_ptr = lookup_chain_config(chain_id);
        const auto [block_number, is_latest_block] = co_await core::get_block_number(block_id, tx_database, /*latest_required=*/true);

        state::RemoteState remote_state{*context_.io_context(),
                                        is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database),
                                        block_number};
        EVMExecutor executor{*chain_config_ptr, workers_, remote_state};
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        silkworm::Transaction txn{call.to_transaction()};
        const auto execution_result = co_await executor.call(block_with_hash.block, txn);

        if (execution_result.pre_check_error) {
            reply = make_json_error(request["id"], -32000, execution_result.pre_check_error.value());
        } else if (execution_result.error_code == evmc_status_code::EVMC_SUCCESS) {
            reply = make_json_content(request["id"], "0x" + silkworm::to_hex(execution_result.data));
        } else {
            const auto error_message = EVMExecutor::get_error_message(execution_result.error_code, execution_result.data);
            if (execution_result.data.empty()) {
                reply = make_json_error(request["id"], -32000, error_message);
            } else {
                reply = make_json_error(request["id"], RevertError{{3, error_message}, execution_result.data});
            }
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

// https://eth.wiki/json-rpc/API#eth_maxpriorityfeepergas
awaitable<void> EthereumRpcApi::handle_eth_max_priority_fee_per_gas(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto latest_block_number = co_await core::get_block_number(core::kLatestBlockId, tx_database);
        SILKRPC_INFO << "latest_block_number " << latest_block_number << "\n";

        BlockProvider block_provider = [this, &tx_database](uint64_t block_number) {
            return core::read_block_by_number(*block_cache_, tx_database, block_number);
        };

        GasPriceOracle gas_price_oracle{block_provider};
        auto gas_price = co_await gas_price_oracle.suggested_price(latest_block_number);

        reply = make_json_content(request["id"], to_quantity(gas_price));
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

// https://geth.ethereum.org/docs/rpc/ns-eth#eth_createaccesslist
awaitable<void> EthereumRpcApi::handle_eth_create_access_list(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_call params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto call = params[0].get<Call>();
    const auto block_number_or_hash = params[1].get<BlockNumberOrHash>();

    SILKRPC_DEBUG << "call: " << call << " block_number_or_hash: " << block_number_or_hash << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        ethdb::kv::CachedDatabase cached_database{block_number_or_hash, *tx, *state_cache_};

        const auto block_with_hash = co_await core::read_block_by_number_or_hash(*block_cache_, tx_database, block_number_or_hash);
        const auto chain_id = co_await core::rawdb::read_chain_id(tx_database);
        const auto chain_config_ptr = lookup_chain_config(chain_id);

        const bool is_latest_block = co_await core::get_latest_executed_block_number(tx_database) == block_with_hash.block.header.number;
        const core::rawdb::DatabaseReader& db_reader =
            is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database);
        StateReader state_reader(db_reader);
        state::RemoteState remote_state{*context_.io_context(), db_reader, block_with_hash.block.header.number};

        evmc::address to{};
        if (call.to) {
            to = *(call.to);
        } else {
            uint64_t nonce = 0;
            if (!call.nonce) {
                // Retrieve nonce by txpool
                auto nonce_option = co_await tx_pool_->nonce(*call.from);
                if (!nonce_option) {
                    std::optional<silkworm::Account> account{co_await state_reader.read_account(*call.from, block_with_hash.block.header.number + 1)};
                    if (account) {
                        nonce = (*account).nonce;  // NOLINT
                    }
                } else {
                    nonce = *nonce_option + 1;
                }
                call.nonce = nonce;
            } else {
                nonce = *(call.nonce);  // NOLINT
            }
            to = silkworm::create_address(*call.from, nonce);
        }

        auto tracer = std::make_shared<AccessListTracer>(*call.from, to);

        Tracers tracers{tracer};
        bool access_lists_match{false};
        do {
            EVMExecutor executor{*chain_config_ptr, workers_, remote_state};
            const auto txn = call.to_transaction();
            tracer->reset_access_list();
            const auto execution_result = co_await executor.call(block_with_hash.block, txn, tracers, /* refund */ true, /* gasBailout */ false);
            if (execution_result.pre_check_error) {
                reply = make_json_error(request["id"], -32000, execution_result.pre_check_error.value());
                break;
            }
            const AccessList& current_access_list = tracer->get_access_list();
            if (call.access_list == current_access_list) {
                access_lists_match = true;
                AccessListResult access_list_result;
                access_list_result.access_list = current_access_list;
                access_list_result.gas_used = txn.gas_limit - execution_result.gas_left;
                if (execution_result.error_code != evmc_status_code::EVMC_SUCCESS) {
                    const auto error_message = EVMExecutor::get_error_message(execution_result.error_code, execution_result.data, false /* full_error */);
                    access_list_result.error = error_message;
                }
                reply = make_json_content(request["id"], access_list_result);
                break;
            }
            call.set_access_list(current_access_list);
        } while (!access_lists_match);
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

// https://docs.flashbots.net/flashbots-auction/miners/mev-geth-spec/v06-rpc/eth_callBundle
awaitable<void> EthereumRpcApi::handle_eth_call_bundle(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 3) {
        auto error_msg = "invalid eth_callBundle params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    auto tx_hash_list = params[0].get<std::vector<evmc::bytes32>>();
    const auto block_number_or_hash = params[1].get<BlockNumberOrHash>();
    const auto timeout = params[2].get<uint64_t>();

    if (tx_hash_list.empty()) {
        const auto error_msg = "invalid eth_callBundle hash list: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    SILKRPC_DEBUG << "block_number_or_hash: " << block_number_or_hash << " timeout: " << timeout << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::kv::CachedDatabase tx_database{block_number_or_hash, *tx, *state_cache_};
        ethdb::kv::CachedDatabase cached_database{block_number_or_hash, *tx, *state_cache_};

        const auto block_with_hash = co_await core::read_block_by_number_or_hash(*block_cache_, tx_database, block_number_or_hash);
        const auto chain_id = co_await core::rawdb::read_chain_id(tx_database);
        const auto chain_config_ptr = lookup_chain_config(chain_id);

        const bool is_latest_block = co_await core::get_latest_executed_block_number(tx_database) == block_with_hash.block.header.number;
        const core::rawdb::DatabaseReader& db_reader =
            is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database);
        auto block_number = block_with_hash.block.header.number;
        state::RemoteState remote_state{*context_.io_context(), db_reader, block_number};

        const auto start_time = clock_time::now();

        struct CallBundleInfo bundle_info {};
        bool error{false};

        silkworm::Bytes hash_data{};

        for (std::size_t i{0}; i < tx_hash_list.size(); i++) {
            struct CallBundleTxInfo tx_info {};
            const auto tx_with_block = co_await core::read_transaction_by_hash(*block_cache_, tx_database, tx_hash_list[i]);
            if (!tx_with_block) {
                const auto error_msg = "invalid transaction hash";
                SILKRPC_ERROR << error_msg << "\n";
                reply = make_json_error(request["id"], 100, error_msg);
                break;
            }

            EVMExecutor executor{*chain_config_ptr, workers_, remote_state};
            const auto execution_result = co_await executor.call(block_with_hash.block, tx_with_block->transaction);
            if (execution_result.pre_check_error) {
                reply = make_json_error(request["id"], -32000, execution_result.pre_check_error.value());
                error = true;
                break;
            }

            if ((clock_time::since(start_time) / 1000000) > timeout) {
                const auto error_msg = "execution aborted (timeout)";
                SILKRPC_ERROR << error_msg << "\n";
                reply = make_json_error(request["id"], -32000, error_msg);
                error = true;
                break;
            }
            tx_info.gas_used = tx_with_block->transaction.gas_limit - execution_result.gas_left;
            tx_info.hash = hash_of_transaction(tx_with_block->transaction);

            if (execution_result.error_code != evmc_status_code::EVMC_SUCCESS) {
                const auto error_message = EVMExecutor::get_error_message(execution_result.error_code, execution_result.data, false /* full_error */);
                tx_info.error_message = error_message;
            } else {
                tx_info.value = silkworm::to_bytes32(execution_result.data);
            }

            bundle_info.txs_info.push_back(tx_info);
            hash_data.append({tx_info.hash.bytes, silkworm::kHashLength});
        }
        if (!error) {
            bundle_info.bundle_hash = hash_of(hash_data);
            reply = make_json_content(request["id"], bundle_info);
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

// https://eth.wiki/json-rpc/API#eth_newfilter
awaitable<void> EthereumRpcApi::handle_eth_new_filter(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_newFilter params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto filter = params[0].get<StoredFilter>();
    SILKRPC_DEBUG << "filter: " << filter << "\n";

    if ((filter.from_block && filter.from_block.value() == core::kPendingBlockId) ||
        (filter.to_block && filter.to_block.value() == core::kPendingBlockId)) {
        reply = make_json_error(request["id"], -32002, "pending logs not supported");
        co_return;
    }

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto [start, end] = co_await get_block_numbers(filter, tx_database);
        filter.start = start;
        filter.end = end;

        const auto filter_id = filter_storage_.add_filter(filter);
        SILKRPC_INFO << "Added a new filter, storage size: " << filter_storage_.size() << "\n";

        if (filter_id) {
            reply = make_json_content(request["id"], filter_id.value());
        } else {
            reply = make_json_error(request["id"], -32000, "TODO");
        }
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

// https://eth.wiki/json-rpc/API#eth_newblockfilter
awaitable<void> EthereumRpcApi::handle_eth_new_block_filter(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        reply = make_json_content(request["id"], to_quantity(0));
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

// https://eth.wiki/json-rpc/API#eth_newpendingtransactionfilter
awaitable<void> EthereumRpcApi::handle_eth_new_pending_transaction_filter(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        reply = make_json_content(request["id"], to_quantity(0));
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

// https://eth.wiki/json-rpc/API#eth_getfilterlogs
awaitable<void> EthereumRpcApi::handle_eth_get_filter_logs(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getFilterLogs params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto filter_id = params[0].get<std::string>();
    SILKRPC_INFO << "filter_id: " << filter_id << "\n";

    const auto filter_ref = filter_storage_.get_filter(filter_id);
    if (!filter_ref) {
        reply = make_json_error(request["id"], -32000, "filter not found");
        co_return;
    }

    auto& filter = filter_ref->get();

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto [start, end] = co_await get_block_numbers(filter, tx_database);

        if (filter.start != start && filter.end != end) {
            filter.logs.clear();
            co_await get_logs(tx_database, start, end, filter.addresses, filter.topics, filter.logs);
        } else {
            co_await get_logs(tx_database, start, end, filter.addresses, filter.topics, filter.logs);
        }
        filter.start = start;
        filter.end = end;

        reply = make_json_content(request["id"], filter.logs);
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

// https://eth.wiki/json-rpc/API#eth_getfilterchanges
awaitable<void> EthereumRpcApi::handle_eth_get_filter_changes(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getFilterChanges params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto filter_id = params[0].get<std::string>();
    SILKRPC_INFO << "filter_id: " << filter_id << "\n";

    const auto filter_opt = filter_storage_.get_filter(filter_id);

    if (!filter_opt) {
        reply = make_json_error(request["id"], -32000, "filter not found");
        co_return;
    }

    auto& filter = filter_opt.value().get();
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto [start, end] = co_await get_block_numbers(filter, tx_database);

        std::vector<Log> logs;
        if (filter.start == start && filter.end != end) {
            co_await get_logs(tx_database, start, end, filter.addresses, filter.topics, logs);
            filter.logs.insert(filter.logs.end(), logs.begin(), logs.end());
        } else if (filter.start != start && filter.end != end) {
            co_await get_logs(tx_database, start, end, filter.addresses, filter.topics, logs);
            filter.logs.clear();
            filter.logs.insert(filter.logs.end(), logs.begin(), logs.end());
        }
        filter.start = start;
        filter.end = end;

        reply = make_json_content(request["id"], logs);
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

// https://eth.wiki/json-rpc/API#eth_uninstallfilter
awaitable<void> EthereumRpcApi::handle_eth_uninstall_filter(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_uninstallFilter params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto filter_id = params[0].get<std::string>();
    SILKRPC_DEBUG << "filter_id: " << filter_id << "\n";

    const auto success = filter_storage_.remove_filter(filter_id);

    SILKRPC_INFO << "Removing filter " << (success ? "succedeed" : "failed") << ", storage size: " << filter_storage_.size() << "\n";

    reply = make_json_content(request["id"], success);

    co_return;
}

// https://eth.wiki/json-rpc/API#eth_getlogs
awaitable<void> EthereumRpcApi::handle_eth_get_logs(const nlohmann::json& request, std::string& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILKRPC_ERROR << error_msg << request.dump() << "\n";
        make_glaze_json_error(reply, request["id"], -32602, error_msg);
        co_return;
    }
    auto params = request["params"];
    if (params.size() > 1) {
        auto error_msg = "too many arguments, want at most 1";
        SILKRPC_ERROR << error_msg << request.dump() << "\n";
        make_glaze_json_error(reply, request["id"], -32602, error_msg);
        co_return;
    }

    auto filter = params[0].get<Filter>();
    SILKRPC_DEBUG << "filter: " << filter << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto [start, end] = co_await get_block_numbers(filter, tx_database);
        if (start == end && start == std::numeric_limits<std::uint64_t>::max()) {
            auto error_msg = "invalid eth_getLogs filter block_hash: " + filter.block_hash.value();
            SILKRPC_ERROR << error_msg << "\n";
            reply = make_json_error(request["id"], 100, error_msg);
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }

        std::vector<Log> logs;
        co_await get_logs(tx_database, start, end, filter.addresses, filter.topics, logs);

        make_glaze_json_content(reply, request["id"], logs);
    } catch (const std::invalid_argument& iv) {
        SILKRPC_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump() << "\n";
        std::vector<silkworm::rpc::Log> log{};
        make_glaze_json_content(reply, request["id"], log);
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        make_glaze_json_error(reply, request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        make_glaze_json_error(reply, request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#eth_sendrawtransaction
awaitable<void> EthereumRpcApi::handle_eth_send_raw_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_sendRawTransaction params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto encoded_tx_string = params[0].get<std::string>();
    const auto encoded_tx_bytes = silkworm::from_hex(encoded_tx_string);
    if (!encoded_tx_bytes.has_value()) {
        const auto error_msg = "invalid eth_sendRawTransaction encoded tx: " + encoded_tx_string;
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], -32602, error_msg);
        co_return;
    }

    silkworm::ByteView encoded_tx_view{*encoded_tx_bytes};
    Transaction txn;
    const auto decoding_result{silkworm::rlp::decode<silkworm::Transaction>(encoded_tx_view, txn)};
    if (!decoding_result) {
        const auto error_msg = decoding_result_to_string(decoding_result.error());
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], -32000, error_msg);
        co_return;
    }

    const float kTxFeeCap = 1;  // 1 ether

    if (!check_tx_fee_less_cap(kTxFeeCap, txn.max_fee_per_gas, txn.gas_limit)) {
        const auto error_msg = "tx fee exceeds the configured cap";
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], -32000, error_msg);
        co_return;
    }

    if (!is_replay_protected(txn)) {
        const auto error_msg = "only replay-protected (EIP-155) transactions allowed over RPC";
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], -32000, error_msg);
        co_return;
    }

    const silkworm::ByteView encoded_tx{*encoded_tx_bytes};
    const auto result = co_await tx_pool_->add_transaction(encoded_tx);
    if (!result.success) {
        SILKRPC_ERROR << "cannot add transaction: " << result.error_descr << "\n";
        reply = make_json_error(request["id"], -32000, result.error_descr);
        co_return;
    }

    txn.recover_sender();
    if (!txn.from.has_value()) {
        const auto error_msg = "cannot recover sender";
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], -32000, error_msg);
        co_return;
    }

    const auto ethash_hash{hash_of_transaction(txn)};
    const auto hash = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
    if (!txn.to.has_value()) {
        const auto contract_address = silkworm::create_address(*txn.from, txn.nonce);
        SILKRPC_DEBUG << "submitted contract creation hash: " << hash << " from: " << *txn.from << " nonce: " << txn.nonce << " contract: " << contract_address << " value: " << txn.value << "\n";
    } else {
        SILKRPC_DEBUG << "submitted transaction hash: " << hash << " from: " << *txn.from << " nonce: " << txn.nonce << " recipient: " << *txn.to << " value: " << txn.value << "\n";
    }

    reply = make_json_content(request["id"], hash);

    co_return;
}

// https://eth.wiki/json-rpc/API#eth_sendtransaction
awaitable<void> EthereumRpcApi::handle_eth_send_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        reply = make_json_content(request["id"], to_quantity(0));
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

// https://eth.wiki/json-rpc/API#eth_signtransaction
awaitable<void> EthereumRpcApi::handle_eth_sign_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        reply = make_json_content(request["id"], to_quantity(0));
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

// https://eth.wiki/json-rpc/API#eth_getproof
awaitable<void> EthereumRpcApi::handle_eth_get_proof(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        reply = make_json_content(request["id"], to_quantity(0));
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

// https://eth.wiki/json-rpc/API#eth_mining
awaitable<void> EthereumRpcApi::handle_eth_mining(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto mining_result = co_await miner_->get_mining();
        reply = make_json_content(request["id"], mining_result.enabled && mining_result.running);
    } catch (const boost::system::system_error& se) {
        SILKRPC_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, se.code().message());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_return;
}

// https://eth.wiki/json-rpc/API#eth_coinbase
awaitable<void> EthereumRpcApi::handle_eth_coinbase(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto coinbase_address = co_await backend_->etherbase();
        reply = make_json_content(request["id"], coinbase_address);
    } catch (const boost::system::system_error& se) {
        SILKRPC_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, se.code().message());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_return;
}

// https://eth.wiki/json-rpc/API#eth_hashrate
awaitable<void> EthereumRpcApi::handle_eth_hashrate(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto hash_rate = co_await miner_->get_hash_rate();
        reply = make_json_content(request["id"], to_quantity(hash_rate));
    } catch (const boost::system::system_error& se) {
        SILKRPC_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, se.code().message());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_return;
}

// https://eth.wiki/json-rpc/API#eth_submithashrate
awaitable<void> EthereumRpcApi::handle_eth_submit_hashrate(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        const auto error_msg = "invalid eth_submitHashrate params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    try {
        const auto hash_rate = params[0].get<intx::uint256>();
        const auto id = params[1].get<evmc::bytes32>();
        const auto success = co_await miner_->submit_hash_rate(hash_rate, id);
        reply = make_json_content(request["id"], success);
    } catch (const boost::system::system_error& se) {
        SILKRPC_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, se.code().message());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_return;
}

// https://eth.wiki/json-rpc/API#eth_getwork
awaitable<void> EthereumRpcApi::handle_eth_get_work(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto work = co_await miner_->get_work();
        const std::vector<std::string> current_work{
            silkworm::to_hex(work.header_hash),
            silkworm::to_hex(work.seed_hash),
            silkworm::to_hex(work.target),
            silkworm::to_hex(work.block_number)};
        reply = make_json_content(request["id"], current_work);
    } catch (const boost::system::system_error& se) {
        SILKRPC_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, se.code().message());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_return;
}

// https://eth.wiki/json-rpc/API#eth_submitwork
awaitable<void> EthereumRpcApi::handle_eth_submit_work(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        const auto error_msg = "invalid eth_submitWork params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    try {
        const auto block_nonce = silkworm::from_hex(params[0].get<std::string>());
        if (!block_nonce.has_value()) {
            const auto error_msg = "invalid eth_submitWork params: " + params.dump();
            SILKRPC_ERROR << error_msg << "\n";
            reply = make_json_error(request["id"], 100, error_msg);
            co_return;
        }
        const auto pow_hash = params[1].get<evmc::bytes32>();
        const auto digest = params[2].get<evmc::bytes32>();
        const auto success = co_await miner_->submit_work(block_nonce.value(), pow_hash, digest);
        reply = make_json_content(request["id"], success);
    } catch (const boost::system::system_error& se) {
        SILKRPC_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, se.code().message());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_return;
}

// https://eth.wiki/json-rpc/API#eth_subscribe
awaitable<void> EthereumRpcApi::handle_eth_subscribe(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        reply = make_json_content(request["id"], to_quantity(0));
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

// https://eth.wiki/json-rpc/API#eth_unsubscribe
awaitable<void> EthereumRpcApi::handle_eth_unsubscribe(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        reply = make_json_content(request["id"], to_quantity(0));
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

// https://eth.wiki/json-rpc/API#eth_feehistory
awaitable<void> EthereumRpcApi::handle_fee_history(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        const auto error_msg = "invalid eth_feeHistory params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    uint64_t block_count;
    if (params[0].is_string()) {
        const auto value = params[0].get<std::string>();
        block_count = std::stoul(value, nullptr, 16);
    } else {
        block_count = params[0].get<uint64_t>();
    }
    const auto newest_block = params[1].get<std::string>();
    const auto reward_percentile = params[2].get<std::vector<uint64_t>>();

    SILKRPC_LOG << "block_count: " << block_count 
        << ", newest_block: " << newest_block
        << ", reward_percentile size: " << reward_percentile.size() << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        reply = make_json_content(request["id"], to_quantity(0));
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

awaitable<roaring::Roaring> EthereumRpcApi::get_topics_bitmap(core::rawdb::DatabaseReader& db_reader, FilterTopics& topics, uint64_t start, uint64_t end) {
    SILKRPC_DEBUG << "#topics: " << topics.size() << " start: " << start << " end: " << end << "\n";
    roaring::Roaring result_bitmap;
    for (const auto& subtopics : topics) {
        SILKRPC_DEBUG << "#subtopics: " << subtopics.size() << "\n";
        roaring::Roaring subtopic_bitmap;
        for (auto topic : subtopics) {
            silkworm::Bytes topic_key{std::begin(topic.bytes), std::end(topic.bytes)};
            SILKRPC_TRACE << "topic: " << topic << " topic_key: " << silkworm::to_hex(topic) << "\n";
            auto bitmap = co_await ethdb::bitmap::get(db_reader, db::table::kLogTopicIndexName, topic_key, start, end);
            SILKRPC_TRACE << "bitmap: " << bitmap.toString() << "\n";
            subtopic_bitmap |= bitmap;
            SILKRPC_TRACE << "subtopic_bitmap: " << subtopic_bitmap.toString() << "\n";
        }
        if (!subtopic_bitmap.isEmpty()) {
            if (result_bitmap.isEmpty()) {
                result_bitmap = subtopic_bitmap;
            } else {
                result_bitmap &= subtopic_bitmap;
            }
        }
        SILKRPC_DEBUG << "result_bitmap: " << result_bitmap.toString() << "\n";
    }
    co_return result_bitmap;
}

awaitable<roaring::Roaring> EthereumRpcApi::get_addresses_bitmap(core::rawdb::DatabaseReader& db_reader, FilterAddresses& addresses, uint64_t start, uint64_t end) {
    SILKRPC_TRACE << "#addresses: " << addresses.size() << " start: " << start << " end: " << end << "\n";
    roaring::Roaring result_bitmap;
    for (auto address : addresses) {
        silkworm::Bytes address_key{std::begin(address.bytes), std::end(address.bytes)};
        auto bitmap = co_await ethdb::bitmap::get(db_reader, db::table::kLogAddressIndexName, address_key, start, end);
        SILKRPC_TRACE << "bitmap: " << bitmap.toString() << "\n";
        result_bitmap |= bitmap;
    }
    SILKRPC_TRACE << "result_bitmap: " << result_bitmap.toString() << "\n";
    co_return result_bitmap;
}

awaitable<void> EthereumRpcApi::get_logs(ethdb::TransactionDatabase& tx_database, std::uint64_t start, std::uint64_t end,
                                         FilterAddresses& addresses, FilterTopics& topics, std::vector<Log>& logs) {
    SILKRPC_INFO << "start block: " << start << " end block: " << end << "\n";

    roaring::Roaring block_numbers;
    block_numbers.addRange(start, end + 1);  // [min, max)

    SILKRPC_DEBUG << "block_numbers.cardinality(): " << block_numbers.cardinality() << "\n";

    if (!topics.empty()) {
        auto topics_bitmap = co_await get_topics_bitmap(tx_database, topics, start, end);
        SILKRPC_TRACE << "topics_bitmap: " << topics_bitmap.toString() << "\n";
        if (topics_bitmap.isEmpty()) {
            block_numbers = topics_bitmap;
        } else {
            block_numbers &= topics_bitmap;
        }
    }
    SILKRPC_DEBUG << "block_numbers.cardinality(): " << block_numbers.cardinality() << "\n";
    SILKRPC_TRACE << "block_numbers: " << block_numbers.toString() << "\n";

    if (!addresses.empty()) {
        auto addresses_bitmap = co_await get_addresses_bitmap(tx_database, addresses, start, end);
        if (addresses_bitmap.isEmpty()) {
            block_numbers = addresses_bitmap;
        } else {
            block_numbers &= addresses_bitmap;
        }
    }
    SILKRPC_DEBUG << "block_numbers.cardinality(): " << block_numbers.cardinality() << "\n";
    SILKRPC_TRACE << "block_numbers: " << block_numbers.toString() << "\n";

    if (block_numbers.cardinality() == 0) {
        co_return;
    }

    Logs chunk_logs;
    Logs filtered_chunck_logs;
    Logs filtered_block_logs{};
    chunk_logs.reserve(512);
    filtered_chunck_logs.reserve(64);
    filtered_block_logs.reserve(256);

    for (const auto& block_to_match : block_numbers) {
        uint64_t log_index{0};

        filtered_block_logs.clear();
        const auto block_key = silkworm::db::block_key(block_to_match);
        SILKRPC_TRACE << "block_to_match: " << block_to_match << " block_key: " << silkworm::to_hex(block_key) << "\n";
        co_await tx_database.for_prefix(db::table::kLogsName, block_key, [&](const silkworm::Bytes& k, const silkworm::Bytes& v) {
            chunk_logs.clear();
            const bool decoding_ok{cbor_decode(v, chunk_logs)};
            if (!decoding_ok) {
                return false;
            }
            for (auto& log : chunk_logs) {
                log.index = log_index++;
            }
            SILKRPC_DEBUG << "chunk_logs.size(): " << chunk_logs.size() << "\n";
            filtered_chunck_logs.clear();
            filter_logs(std::move(chunk_logs), addresses, topics, filtered_chunck_logs);
            SILKRPC_DEBUG << "filtered_chunk_logs.size(): " << filtered_chunck_logs.size() << "\n";
            if (filtered_chunck_logs.size() > 0) {
                const auto tx_id = boost::endian::load_big_u32(&k[sizeof(uint64_t)]);
                SILKRPC_DEBUG << "tx_id: " << tx_id << "\n";
                for (auto& log : filtered_chunck_logs) {
                    log.tx_index = tx_id;
                }
                filtered_block_logs.insert(filtered_block_logs.end(), filtered_chunck_logs.begin(), filtered_chunck_logs.end());
            }
            return true;
        });
        SILKRPC_DEBUG << "filtered_block_logs.size(): " << filtered_block_logs.size() << "\n";

        if (!filtered_block_logs.empty()) {
            const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_to_match);
            SILKRPC_DEBUG << "block_hash: " << silkworm::to_hex(block_with_hash.hash) << "\n";
            for (auto& log : filtered_block_logs) {
                const auto tx_hash{hash_of_transaction(block_with_hash.block.transactions[log.tx_index])};
                log.block_number = block_to_match;
                log.block_hash = block_with_hash.hash;
                log.tx_hash = silkworm::to_bytes32({tx_hash.bytes, silkworm::kHashLength});
            }
            logs.insert(logs.end(), filtered_block_logs.begin(), filtered_block_logs.end());
        }
    }
    SILKRPC_INFO << "logs.size(): " << logs.size() << "\n";

    co_return;
}

void EthereumRpcApi::filter_logs(std::vector<Log>&& logs, FilterAddresses& addresses, FilterTopics& topics, std::vector<Log>& filtered_logs) {
    SILKRPC_DEBUG << "addresses: " << addresses << "\n";
    for (auto& log : logs) {
        SILKRPC_DEBUG << "log: " << log << "\n";
        if (!addresses.empty() && std::find(addresses.begin(), addresses.end(), log.address) == addresses.end()) {
            SILKRPC_DEBUG << "skipped log for address: 0x" << silkworm::to_hex(log.address) << "\n";
            continue;
        }
        auto matches = true;
        if (!topics.empty()) {
            if (topics.size() > log.topics.size()) {
                SILKRPC_DEBUG << "#topics: " << topics.size() << " #log.topics: " << log.topics.size() << "\n";
                continue;
            }
            for (size_t i{0}; i < topics.size(); i++) {
                SILKRPC_DEBUG << "log.topics[i]: " << log.topics[i] << "\n";
                auto subtopics = topics[i];
                auto matches_subtopics = subtopics.empty();  // empty rule set == wildcard
                SILKRPC_TRACE << "matches_subtopics: " << std::boolalpha << matches_subtopics << "\n";
                for (auto& topic : subtopics) {
                    SILKRPC_DEBUG << "topic: " << topic << "\n";
                    if (log.topics[i] == topic) {
                        matches_subtopics = true;
                        SILKRPC_TRACE << "matches_subtopics: " << matches_subtopics << "\n";
                        break;
                    }
                }
                if (!matches_subtopics) {
                    SILKRPC_TRACE << "No subtopic matches\n";
                    matches = false;
                    break;
                }
            }
        }
        SILKRPC_DEBUG << "matches: " << matches << "\n";
        if (matches) {
            filtered_logs.push_back(std::move(log));
        }
    }
}

}  // namespace silkworm::rpc::commands
