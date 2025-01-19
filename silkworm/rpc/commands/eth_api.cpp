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
#include <limits>
#include <map>
#include <string>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/db/kv/state_reader.hpp>
#include <silkworm/execution/state_factory.hpp>
#include <silkworm/infra/common/clock_time.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/call_many.hpp>
#include <silkworm/rpc/core/estimate_gas_oracle.hpp>
#include <silkworm/rpc/core/evm_access_list_tracer.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/core/fee_history_oracle.hpp>
#include <silkworm/rpc/core/gas_price_oracle.hpp>
#include <silkworm/rpc/core/logs_walker.hpp>
#include <silkworm/rpc/core/receipts.hpp>
#include <silkworm/rpc/protocol/errors.hpp>
#include <silkworm/rpc/stagedsync/stages.hpp>

namespace silkworm::rpc::commands {

using db::kv::StateReader;

// https://eth.wiki/json-rpc/API#eth_blocknumber
Task<void> EthereumRpcApi::handle_eth_block_num(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();
    const auto chain_storage = tx->create_storage();
    rpc::BlockReader block_reader{*chain_storage, *tx};

    try {
        const auto block_num = co_await block_reader.get_latest_block_num();
        reply = make_json_content(request, to_quantity(block_num));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_chainid
Task<void> EthereumRpcApi::handle_eth_chain_id(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        const auto chain_config = co_await chain_storage->read_chain_config();
        reply = make_json_content(request, to_quantity(chain_config.chain_id));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_protocolversion
Task<void> EthereumRpcApi::handle_eth_protocol_version(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto protocol_version = co_await backend_->protocol_version();
        reply = make_json_content(request, to_quantity(protocol_version));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#eth_syncing
Task<void> EthereumRpcApi::handle_eth_syncing(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();
    const auto chain_storage = tx->create_storage();
    rpc::BlockReader block_reader{*chain_storage, *tx};

    try {
        const auto current_block_num = co_await block_reader.get_current_block_num();
        const auto max_block_num = co_await block_reader.get_max_block_num();
        if (current_block_num >= max_block_num) {
            reply = make_json_content(request, false);
        } else {
            SyncingData syncing_data{};

            syncing_data.current_block = to_quantity(current_block_num);
            syncing_data.max_block = to_quantity(max_block_num);
            for (const char* stage_name : silkworm::db::stages::kAllStages) {
                StageData current_stage;
                current_stage.stage_name = stage_name;
                current_stage.block_num = to_quantity(co_await stages::get_sync_stage_progress(*tx, string_to_bytes(current_stage.stage_name)));
                syncing_data.stages.push_back(current_stage);
            }
            reply = make_json_content(request, syncing_data);
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_gasprice
Task<void> EthereumRpcApi::handle_eth_gas_price(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};
        tx->set_state_cache_enabled(/*cache_enabled=*/true);  // always at latest block

        const auto latest_block_num = co_await block_reader.get_block_num(kLatestBlockId);
        SILK_TRACE << "latest_block_num " << latest_block_num;

        BlockProvider block_provider = [this, &chain_storage](BlockNum block_num) {
            return core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        };

        GasPriceOracle gas_price_oracle{block_provider};
        auto gas_price = co_await gas_price_oracle.suggested_price(latest_block_num);

        const auto block_with_hash = co_await block_provider(latest_block_num);
        if (block_with_hash) {
            const auto base_fee = block_with_hash->block.header.base_fee_per_gas.value_or(0);
            gas_price += base_fee;
            reply = make_json_content(request, to_quantity(gas_price));
        } else {
            reply = make_json_error(request, 100, "invalid block id");
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getblockbyhash
Task<void> EthereumRpcApi::handle_eth_get_block_by_hash(const nlohmann::json& request, std::string& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getBlockByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }
    auto block_hash = params[0].get<evmc::bytes32>();
    auto full_tx = params[1].get<bool>();
    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash) << " full_tx: " << std::boolalpha << full_tx;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (block_with_hash) {
            BlockNum block_num = block_with_hash->block.header.number;
            const auto total_difficulty{co_await chain_storage->read_total_difficulty(block_with_hash->hash, block_num)};
            const Block extended_block{block_with_hash, full_tx, total_difficulty};
            make_glaze_json_content(request, extended_block, reply);
        } else {
            make_glaze_json_null_content(request, reply);
        }
    } catch (const std::invalid_argument&) {
        make_glaze_json_null_content(request, reply);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        make_glaze_json_error(request, kInternalError, e.what(), reply);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        make_glaze_json_error(request, kServerError, "unexpected exception", reply);
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getblockbynumber
Task<void> EthereumRpcApi::handle_eth_get_block_by_number(const nlohmann::json& request, std::string& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getBlockByNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    auto full_tx = params[1].get<bool>();
    SILK_DEBUG << "block_id: " << block_id << " full_tx: " << std::boolalpha << full_tx;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num = co_await block_reader.get_block_num(block_id);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (block_with_hash) {
            const auto total_difficulty{co_await chain_storage->read_total_difficulty(block_with_hash->hash, block_num)};
            const Block extended_block{block_with_hash, full_tx, total_difficulty};

            make_glaze_json_content(request, extended_block, reply);
        } else {
            make_glaze_json_null_content(request, reply);
        }
    } catch (const std::invalid_argument&) {
        make_glaze_json_null_content(request, reply);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        make_glaze_json_error(request, kInternalError, e.what(), reply);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        make_glaze_json_error(request, kServerError, "unexpected exception", reply);
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getblocktransactioncountbyhash
Task<void> EthereumRpcApi::handle_eth_get_block_transaction_count_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getBlockTransactionCountByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    auto block_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash);

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (block_with_hash) {
            const auto tx_count = block_with_hash->block.transactions.size();
            reply = make_json_content(request, to_quantity(tx_count));
        } else {
            reply = make_json_content(request, nullptr);
        }
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, nullptr);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getblocktransactioncountbynumber
Task<void> EthereumRpcApi::handle_eth_get_block_transaction_count_by_number(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getBlockTransactionCountByNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num = co_await block_reader.get_block_num(block_id);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (block_with_hash) {
            const auto tx_count = block_with_hash->block.transactions.size();
            reply = make_json_content(request, to_quantity(tx_count));
        } else {
            reply = make_json_content(request, nullptr);
        }
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, nullptr);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getunclebyblockhashandindex
Task<void> EthereumRpcApi::handle_eth_get_uncle_by_block_hash_and_index(const nlohmann::json& request, std::string& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getUncleByBlockHashAndIndex params: " + params.dump();
        SILK_ERROR << error_msg;
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    const auto index = params[1].get<std::string>();
    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash) << " index: " << index;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (block_with_hash) {
            const auto ommers = block_with_hash->block.ommers;

            const auto idx = std::stoul(index, nullptr, 16);
            if (idx >= ommers.size()) {
                SILK_WARN << "invalid_argument: index not found processing request: " << request.dump();
                make_glaze_json_null_content(request, reply);
            } else {
                const auto& uncle = ommers[idx];

                auto uncle_block_with_hash = std::make_shared<BlockWithHash>();
                uncle_block_with_hash->block.ommers.push_back(uncle);
                uncle_block_with_hash->hash = uncle.hash();
                const Block uncle_block_with_hash_and_td{uncle_block_with_hash};

                make_glaze_json_content(request, uncle_block_with_hash_and_td, reply);
            }
        } else {
            make_glaze_json_null_content(request, reply);
        }
    } catch (const std::invalid_argument&) {
        make_glaze_json_null_content(request, reply);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        make_glaze_json_error(request, kInternalError, e.what(), reply);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        make_glaze_json_error(request, kServerError, "unexpected exception", reply);
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getunclebyblocknumberandindex
Task<void> EthereumRpcApi::handle_eth_get_uncle_by_block_num_and_index(const nlohmann::json& request, std::string& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getUncleByBlockNumberAndIndex params: " + params.dump();
        SILK_ERROR << error_msg;
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    const auto index = params[1].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id << " index: " << index;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num = co_await block_reader.get_block_num(block_id);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (block_with_hash) {
            const auto ommers = block_with_hash->block.ommers;

            const auto idx = std::stoul(index, nullptr, 16);
            if (idx >= ommers.size()) {
                SILK_WARN << "invalid_argument: index not found processing request: " << request.dump();
                make_glaze_json_null_content(request, reply);
            } else {
                const auto& uncle = ommers[idx];

                auto uncle_block_with_hash = std::make_shared<BlockWithHash>();
                uncle_block_with_hash->block.ommers.push_back(uncle);
                uncle_block_with_hash->hash = uncle.hash();
                const Block uncle_block_with_hash_and_td{uncle_block_with_hash};

                make_glaze_json_content(request, uncle_block_with_hash_and_td, reply);
            }
        } else {
            make_glaze_json_null_content(request, reply);
        }
    } catch (const std::invalid_argument&) {
        make_glaze_json_null_content(request, reply);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        make_glaze_json_error(request, kInternalError, e.what(), reply);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        make_glaze_json_error(request, kServerError, "unexpected exception", reply);
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getunclecountbyblockhash
Task<void> EthereumRpcApi::handle_eth_get_uncle_count_by_block_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getUncleCountByBlockHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    auto block_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash);

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (!block_with_hash) {
            reply = make_json_content(request, nullptr);
        } else {
            const auto ommers = block_with_hash->block.ommers.size();
            reply = make_json_content(request, to_quantity(ommers));
        }
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, nullptr);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getunclecountbyblocknumber
Task<void> EthereumRpcApi::handle_eth_get_uncle_count_by_block_num(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getUncleCountByBlockNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num = co_await block_reader.get_block_num(block_id);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (!block_with_hash) {
            reply = make_json_content(request, nullptr);
        } else {
            const auto ommers = block_with_hash->block.ommers.size();
            reply = make_json_content(request, to_quantity(ommers));
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_gettransactionbyhash
Task<void> EthereumRpcApi::handle_eth_get_transaction_by_hash(const nlohmann::json& request, std::string& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getTransactionByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }
    auto transaction_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "transaction_hash: " << silkworm::to_hex(transaction_hash);

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        const auto tx_with_block = co_await core::read_transaction_by_hash(*block_cache_, *chain_storage, transaction_hash);
        if (!tx_with_block) {
            const auto tx_rlp_buffer = co_await tx_pool_->get_transaction(transaction_hash);
            if (tx_rlp_buffer) {
                silkworm::ByteView encoded_tx_view{*tx_rlp_buffer};
                Transaction transaction;
                const auto decoding_result = silkworm::rlp::decode(encoded_tx_view, transaction);
                if (decoding_result) {
                    transaction.queued_in_pool = true;
                    make_glaze_json_content(request, transaction, reply);
                } else {
                    const auto error_msg = "invalid RLP decoding for tx hash: " + silkworm::to_hex(transaction_hash);
                    SILK_ERROR << error_msg;
                    make_glaze_json_null_content(request, reply);
                }
            } else {
                const auto error_msg = "tx hash: " + silkworm::to_hex(transaction_hash) + " does not exist in pool";
                SILK_ERROR << error_msg;
                make_glaze_json_null_content(request, reply);
            }
        } else {
            make_glaze_json_content(request, tx_with_block->transaction, reply);
        }
    } catch (const std::invalid_argument&) {
        make_glaze_json_null_content(request, reply);
    } catch (const boost::system::system_error& se) {
        make_glaze_json_null_content(request, reply);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        make_glaze_json_error(request, kInternalError, e.what(), reply);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        make_glaze_json_error(request, kServerError, "unexpected exception", reply);
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getrawtransactionbyhash
Task<void> EthereumRpcApi::handle_eth_get_raw_transaction_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getRawTransactionByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto transaction_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "transaction_hash: " << silkworm::to_hex(transaction_hash);

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        const auto tx_with_block = co_await core::read_transaction_by_hash(*block_cache_, *chain_storage, transaction_hash);
        if (!tx_with_block) {
            const auto tx_rlp_buffer = co_await tx_pool_->get_transaction(transaction_hash);
            if (tx_rlp_buffer) {
                Rlp rlp{*tx_rlp_buffer};
                reply = make_json_content(request, rlp);
            } else {
                const auto error_msg = "tx hash: " + silkworm::to_hex(transaction_hash) + " does not exist in pool";
                SILK_ERROR << error_msg;
                reply = make_json_error(request, 100, error_msg);
            }
        } else {
            Rlp rlp{};
            silkworm::rlp::encode(rlp.buffer, tx_with_block->transaction, false);
            reply = make_json_content(request, rlp);
        }
    } catch (const std::invalid_argument&) {
        Rlp rlp{};
        reply = make_json_content(request, rlp);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_gettransactionbyblockhashandindex
Task<void> EthereumRpcApi::handle_eth_get_transaction_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getTransactionByBlockHashAndIndex params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    const auto index = params[1].get<std::string>();
    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash) << " index: " << index;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (block_with_hash) {
            const auto& transactions = block_with_hash->block.transactions;

            const auto idx = std::stoul(index, nullptr, 16);
            if (idx >= transactions.size()) {
                SILK_WARN << "Transaction not found for index: " << index;
                reply = make_json_content(request, nullptr);
            } else {
                const auto& block_header = block_with_hash->block.header;
                rpc::Transaction txn{transactions[idx], block_with_hash->hash, block_header.number, block_header.base_fee_per_gas, idx};
                reply = make_json_content(request, txn);
            }
        } else {
            reply = make_json_content(request, nullptr);
        }
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, nullptr);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getrawtransactionbyblockhashandindex
Task<void> EthereumRpcApi::handle_eth_get_raw_transaction_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getRawTransactionByBlockHashAndIndex params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    const auto index = params[1].get<std::string>();
    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash) << " index: " << index;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (block_with_hash) {
            const auto& transactions = block_with_hash->block.transactions;
            const auto idx = std::stoul(index, nullptr, 16);
            if (idx >= transactions.size()) {
                SILK_WARN << "Transaction not found for index: " << index;
                Rlp rlp{};
                reply = make_json_content(request, rlp);
            } else {
                Rlp rlp{};
                silkworm::rlp::encode(rlp.buffer, transactions[idx], false);
                reply = make_json_content(request, rlp);
            }
        } else {
            Rlp rlp{};
            reply = make_json_content(request, rlp);
        }
    } catch (const std::invalid_argument&) {
        Rlp rlp{};
        reply = make_json_content(request, rlp);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_gettransactionbyblocknumberandindex
Task<void> EthereumRpcApi::handle_eth_get_transaction_by_block_num_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getTransactionByBlockNumberAndIndex params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    const auto index = params[1].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id << " index: " << index;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num = co_await block_reader.get_block_num(block_id);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (block_with_hash) {
            const auto& transactions = block_with_hash->block.transactions;

            const auto idx = std::stoul(index, nullptr, 16);
            if (idx >= transactions.size()) {
                SILK_WARN << "Transaction not found for index: " << index;
                reply = make_json_content(request, nullptr);
            } else {
                const auto block_header = block_with_hash->block.header;
                rpc::Transaction txn{transactions[idx], block_with_hash->hash, block_header.number, block_header.base_fee_per_gas, idx};
                reply = make_json_content(request, txn);
            }
        } else {
            Rlp rlp{};
            reply = make_json_content(request, rlp);
        }
    } catch (const std::invalid_argument&) {
        Rlp rlp{};
        reply = make_json_content(request, rlp);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getrawtransactionbyblocknumberandindex
Task<void> EthereumRpcApi::handle_eth_get_raw_transaction_by_block_num_and_index(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getRawTransactionByBlockNumberAndIndex params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    const auto index = params[1].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id << " index: " << index;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};
        const auto block_num = co_await block_reader.get_block_num(block_id);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (block_with_hash) {
            const auto& transactions = block_with_hash->block.transactions;

            const auto idx = std::stoul(index, nullptr, 16);
            if (idx >= transactions.size()) {
                SILK_WARN << "Transaction not found for index: " << index;
                Rlp rlp{};
                reply = make_json_content(request, rlp);
            } else {
                Rlp rlp{};
                silkworm::rlp::encode(rlp.buffer, transactions[idx], false);
                reply = make_json_content(request, rlp);
            }
        } else {
            Rlp rlp{};
            reply = make_json_content(request, rlp);
        }
    } catch (const std::invalid_argument&) {
        Rlp rlp{};
        reply = make_json_content(request, rlp);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_gettransactionreceipt
Task<void> EthereumRpcApi::handle_eth_get_transaction_receipt(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getTransactionReceipt params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    auto transaction_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "transaction_hash: " << silkworm::to_hex(transaction_hash);
    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();

        const auto block_with_hash = co_await core::read_block_by_transaction_hash(*block_cache_, *chain_storage, transaction_hash);
        if (!block_with_hash) {
            reply = make_json_content(request, {});
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        auto receipts = co_await core::get_receipts(*tx, *block_with_hash, *chain_storage, workers_);
        const auto& transactions = block_with_hash->block.transactions;
        if (receipts.size() != transactions.size()) {
            throw std::invalid_argument{"Unexpected size for receipts in handle_eth_get_transaction_receipt"};
        }

        std::optional<size_t> tx_index;
        for (size_t idx{0}; idx < transactions.size(); ++idx) {
            auto ethash_hash = transactions[idx].hash();

            SILK_TRACE << "tx " << idx << ") hash: " << silkworm::to_hex(silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength}));
            if (std::memcmp(transaction_hash.bytes, ethash_hash.bytes, silkworm::kHashLength) == 0) {
                tx_index = idx;
                const intx::uint256 base_fee_per_gas{block_with_hash->block.header.base_fee_per_gas.value_or(0)};
                const intx::uint256 effective_gas_price{transactions[idx].max_fee_per_gas >= base_fee_per_gas ? transactions[idx].effective_gas_price(base_fee_per_gas)
                                                                                                              : transactions[idx].max_priority_fee_per_gas};
                receipts[idx].effective_gas_price = effective_gas_price;
                break;
            }
        }
        if (!tx_index) {
            throw std::invalid_argument{"Unexpected transaction index in handle_eth_get_transaction_receipt"};
        }
        reply = make_json_content(request, receipts[*tx_index]);
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, {});
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_content(request, {});
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_estimategas
Task<void> EthereumRpcApi::handle_eth_estimate_gas(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() > 2 || params.empty()) {
        auto error_msg = "invalid eth_estimateGas params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto call = params[0].get<Call>();
    SILK_DEBUG << "call: " << call;

    auto tx = co_await database_->begin_transaction();
    const auto chain_storage{tx->create_storage()};
    rpc::BlockReader block_reader{*chain_storage, *tx};

    std::optional<BlockNum> block_num_for_gas_limit;
    if (params.size() == 2) {
        const auto block_id = params[1].get<std::string>();
        SILK_DEBUG << "block_id: " << block_id;
        block_num_for_gas_limit = co_await block_reader.get_block_num(block_id);
    }

    try {
        tx->set_state_cache_enabled(/*cache_enabled=*/true);  // always at latest block

        const BlockNumOrHash block_num_or_hash{kLatestBlockId};

        const auto chain_config = co_await chain_storage->read_chain_config();
        const auto latest_block_num = co_await block_reader.get_block_num(kLatestBlockId);
        SILK_DEBUG << "chain_id: " << chain_config.chain_id << ", latest_block_num: " << latest_block_num;

        const auto latest_block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, latest_block_num);
        if (!latest_block_with_hash) {
            reply = make_json_error(request, 100, "block not found");
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        const auto latest_block = latest_block_with_hash->block;

        rpc::BlockHeaderProvider block_header_provider = [&chain_storage](BlockNum block_num) {
            return chain_storage->read_canonical_header(block_num);
        };

        rpc::AccountReader account_reader = [&tx](const evmc::address& address, TxnId txn_id) -> Task<std::optional<Account>> {
            StateReader state_reader{*tx, txn_id};
            co_return co_await state_reader.read_account(address);
        };

        execution::StateFactory state_factory{*tx};
        const auto txn_id = co_await state_factory.user_txn_id_at(latest_block.header.number);

        rpc::EstimateGasOracle estimate_gas_oracle{block_header_provider, account_reader, chain_config, workers_, *tx, *chain_storage};
        const auto estimated_gas = co_await estimate_gas_oracle.estimate_gas(call, latest_block, txn_id, block_num_for_gas_limit);

        reply = make_json_content(request, to_quantity(estimated_gas));
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, to_quantity(0));
    } catch (const rpc::EstimateGasException& e) {
        SILK_ERROR << "EstimateGasException: code: " << e.error_code() << " message: " << e.message() << " processing request: " << request.dump();
        if (e.data().empty()) {
            reply = make_json_error(request, static_cast<int>(e.error_code()), e.message());
        } else {
            reply = make_json_error(request, RevertError{{3, e.message()}, e.data()});
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getbalance
Task<void> EthereumRpcApi::handle_eth_get_balance(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getBalance params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto address = params[0].get<evmc::address>();
    const auto block_id = params[1].get<std::string>();
    SILK_DEBUG << "address: " << address << " block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num_or_hash = BlockNumOrHash{block_id};
        const auto [block_num, is_latest_block] = co_await block_reader.get_block_num(block_num_or_hash);
        tx->set_state_cache_enabled(is_latest_block);

        std::optional<TxnId> txn_id;
        if (!is_latest_block) {
            execution::StateFactory state_factory{*tx};
            txn_id = co_await state_factory.user_txn_id_at(block_num + 1);
        }
        StateReader state_reader{*tx, txn_id};

        std::optional<silkworm::Account> account{co_await state_reader.read_account(address)};

        reply = make_json_content(request, "0x" + (account ? intx::hex(account->balance) : "0"));
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, "0x0");
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getcode
Task<void> EthereumRpcApi::handle_eth_get_code(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getCode params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto address = params[0].get<evmc::address>();
    const auto block_id = params[1].get<std::string>();
    SILK_DEBUG << "address: " << address << " block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto [block_num, is_latest_block] = co_await block_reader.get_block_num(block_id, /*latest_required=*/true);
        tx->set_state_cache_enabled(is_latest_block);

        std::optional<TxnId> txn_id;
        if (!is_latest_block) {
            execution::StateFactory state_factory{*tx};
            txn_id = co_await state_factory.user_txn_id_at(block_num + 1);
        }

        StateReader state_reader{*tx, txn_id};
        std::optional<silkworm::Account> account{co_await state_reader.read_account(address)};

        if (account) {
            auto code{co_await state_reader.read_code(address, account->code_hash)};
            reply = make_json_content(request, code ? ("0x" + silkworm::to_hex(*code)) : "0x");
        } else {
            reply = make_json_content(request, "0x");
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_gettransactioncount
Task<void> EthereumRpcApi::handle_eth_get_transaction_count(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_getTransactionCount params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto address = params[0].get<evmc::address>();
    const auto block_id = params[1].get<std::string>();
    SILK_DEBUG << "address: " << address << " block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};
        const auto [block_num, is_latest_block] = co_await block_reader.get_block_num(block_id, /*latest_required=*/true);
        tx->set_state_cache_enabled(is_latest_block);

        std::optional<TxnId> txn_id;
        if (!is_latest_block) {
            execution::StateFactory state_factory{*tx};
            txn_id = co_await state_factory.user_txn_id_at(block_num + 1);
        }

        StateReader state_reader{*tx, txn_id};

        std::optional<silkworm::Account> account{co_await state_reader.read_account(address)};

        if (account) {
            reply = make_json_content(request, to_quantity(account->nonce));
        } else {
            reply = make_json_content(request, "0x0");
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getstorageat
Task<void> EthereumRpcApi::handle_eth_get_storage_at(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3 || !is_valid_address(params[0].get<std::string>())) {
        const auto error_msg = "invalid eth_getStorageAt params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto address = params[0].get<evmc::address>();
    const auto position = params[1].get<std::string>();
    if (!is_valid_hex(position) || position.length() > 2 + kHashLength * 2) {
        const auto error_msg = "invalid position in eth_getStorageAt params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto location = bytes32_from_hex(position);
    const auto block_id = params[2].get<std::string>();
    SILK_DEBUG << "address: " << address << " block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};
        const auto [block_num, is_latest_block] = co_await block_reader.get_block_num(block_id, /*latest_required=*/true);
        tx->set_state_cache_enabled(is_latest_block);

        std::optional<TxnId> txn_id;
        if (!is_latest_block) {
            execution::StateFactory state_factory{*tx};
            txn_id = co_await state_factory.user_txn_id_at(block_num + 1);
        }

        StateReader state_reader{*tx, txn_id};
        std::optional<silkworm::Account> account{co_await state_reader.read_account(address)};

        if (account) {
            auto storage{co_await state_reader.read_storage(address, account->incarnation, location)};
            reply = make_json_content(request, "0x" + silkworm::to_hex(storage));
        } else {
            reply = make_json_content(request, "0x0000000000000000000000000000000000000000000000000000000000000000");
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_call
Task<void> EthereumRpcApi::handle_eth_call(const nlohmann::json& request, std::string& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILK_ERROR << error_msg << request.dump();
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid eth_call params: " + params.dump();
        SILK_ERROR << error_msg;
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }
    const auto call = params[0].get<Call>();
    const auto block_id = params[1].get<std::string>();
    SILK_DEBUG << "call: " << call << " block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};
        const auto chain_config = co_await chain_storage->read_chain_config();
        const auto [block_num, is_latest_block] = co_await block_reader.get_block_num(block_id, /*latest_required=*/true);
        tx->set_state_cache_enabled(/*cache_enabled=*/is_latest_block);

        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (!block_with_hash) {
            make_glaze_json_error(request, 100, "block not found", reply);
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        silkworm::Transaction txn{call.to_transaction()};

        execution::StateFactory state_factory{*tx};
        const auto txn_id = co_await state_factory.user_txn_id_at(block_num + 1);

        const auto execution_result = co_await EVMExecutor::call(
            chain_config, *chain_storage, workers_, block_with_hash->block, txn, txn_id, [&state_factory](auto& io_executor, auto curr_txn_id, auto& storage) {
                return state_factory.create_state(io_executor, storage, curr_txn_id);
            });

        if (execution_result.success()) {
            make_glaze_json_content(request, execution_result.data, reply);
        } else {
            const auto error_message = execution_result.error_message();
            if (execution_result.data.empty()) {
                make_glaze_json_error(request, kServerError, error_message, reply);
            } else {
                make_glaze_json_error(request, RevertError{{3, error_message}, execution_result.data}, reply);
            }
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        make_glaze_json_error(request, kInternalError, e.what(), reply);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        make_glaze_json_error(request, kServerError, "unexpected exception", reply);
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_callMany
Task<void> EthereumRpcApi::handle_eth_call_many(const nlohmann::json& request, nlohmann::json& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required arguments";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, kInvalidParams, error_msg);

        co_return;
    }
    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid eth_callMany params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto bundles = params[0].get<Bundles>();

    if (bundles.empty()) {
        const auto error_msg = "invalid eth_callMany bundle list: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);

        co_return;
    }

    const auto simulation_context = params[1].get<SimulationContext>();

    AccountsOverrides accounts_overrides;
    if (params.size() > 2) {
        from_json(params[2], accounts_overrides);
    }
    std::optional<std::uint64_t> timeout;
    if (params.size() > 3) {
        timeout = params[3].get<std::uint64_t>();
    }

    SILK_TRACE << "bundles: " << bundles
               << " simulation_context: " << simulation_context
               << " accounts_overrides #" << accounts_overrides.size()
               << " timeout: " << timeout.value_or(0);

    auto tx = co_await database_->begin_transaction();

    try {
        call::CallExecutor executor{*tx, *block_cache_, workers_};
        const auto result = co_await executor.execute(bundles, simulation_context, accounts_overrides, timeout);

        if (result.error) {
            reply = make_json_error(request, kServerError, result.error.value());
        } else {
            reply = make_json_content(request, result.results);
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_maxpriorityfeepergas
Task<void> EthereumRpcApi::handle_eth_max_priority_fee_per_gas(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        tx->set_state_cache_enabled(/*cache_enabled=*/true);  // always at latest block

        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto latest_block_num = co_await block_reader.get_block_num(kLatestBlockId);
        SILK_TRACE << "latest_block_num " << latest_block_num;

        BlockProvider block_provider = [this, &chain_storage](BlockNum block_num) {
            return core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        };

        GasPriceOracle gas_price_oracle{block_provider};
        auto gas_price = co_await gas_price_oracle.suggested_price(latest_block_num);

        reply = make_json_content(request, to_quantity(gas_price));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://geth.ethereum.org/docs/rpc/ns-eth#eth_createaccesslist
Task<void> EthereumRpcApi::handle_eth_create_access_list(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2 && params.size() != 3) {
        auto error_msg = "invalid eth_createAccessList params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto call = params[0].get<Call>();
    const auto block_num_or_hash = params[1].get<BlockNumOrHash>();
    bool optimize_gas = true;
    if (params.size() == 3) {
        optimize_gas = params[2];
    }

    SILK_DEBUG << "call: " << call << " block_num_or_hash: " << block_num_or_hash << " optimize: " << optimize_gas;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};
        const auto block_with_hash = co_await core::read_block_by_block_num_or_hash(*block_cache_, *chain_storage, *tx, block_num_or_hash);
        if (!block_with_hash) {
            reply = make_json_content(request, {});
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }

        const auto chain_config = co_await chain_storage->read_chain_config();
        const bool is_latest_block = co_await block_reader.get_latest_executed_block_num() == block_with_hash->block.header.number;
        tx->set_state_cache_enabled(/*cache_enabled=*/is_latest_block);

        execution::StateFactory state_factory{*tx};
        const auto txn_id = co_await state_factory.user_txn_id_at(block_with_hash->block.header.number + 1);

        StateReader state_reader{*tx, txn_id};

        std::optional<uint64_t> nonce = std::nullopt;
        evmc::address to{};
        if (call.to) {
            to = *(call.to);
        } else {
            if (!call.nonce) {
                // Retrieve nonce by txpool
                auto nonce_option = co_await tx_pool_->nonce(*call.from);
                if (!nonce_option) {
                    std::optional<silkworm::Account> account{co_await state_reader.read_account(*call.from)};
                    if (account) {
                        nonce = (*account).nonce + 1;  // NOLINT
                    }
                } else {
                    nonce = *nonce_option + 1;
                }
            } else {
                nonce = *(call.nonce);  // NOLINT
            }
            to = silkworm::create_address(*call.from, *nonce);
        }

        auto tracer = std::make_shared<AccessListTracer>();

        Tracers tracers{tracer};
        auto txn = call.to_transaction(std::nullopt, nonce);
        AccessList saved_access_list = call.access_list;

        while (true) {
            const auto execution_result = co_await EVMExecutor::call(
                chain_config, *chain_storage, workers_, block_with_hash->block, txn, txn_id, [&](auto& io_executor, auto curr_txn_id, auto& storage) {
                    return state_factory.create_state(io_executor, storage, curr_txn_id);
                },
                tracers, /* refund */ true, /* gasBailout */ false);

            if (execution_result.pre_check_error) {
                reply = make_json_error(request, kServerError, execution_result.pre_check_error.value());
                break;
            }
            const AccessList& current_access_list = tracer->get_access_list();
            if (saved_access_list == current_access_list) {
                AccessListResult access_list_result;
                access_list_result.gas_used = txn.gas_limit - execution_result.gas_left;
                if (!execution_result.success()) {
                    access_list_result.error = execution_result.error_message(false /* full_error */);
                }
                if (optimize_gas) {
                    tracer->optimize_gas(*call.from, to, block_with_hash->block.header.beneficiary);
                }
                access_list_result.access_list = current_access_list;
                reply = make_json_content(request, access_list_result);
                break;
            }
            txn = call.to_transaction(current_access_list, nonce);
            saved_access_list = current_access_list;
        }
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, {});
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://docs.flashbots.net/flashbots-auction/advanced/rpc-endpoint#eth_callbundle
Task<void> EthereumRpcApi::handle_eth_call_bundle(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        auto error_msg = "invalid eth_callBundle params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto tx_hash_list = params[0].get<std::vector<evmc::bytes32>>();
    const auto block_num_or_hash = params[1].get<BlockNumOrHash>();
    const auto timeout = params[2].get<uint64_t>();

    if (tx_hash_list.empty()) {
        const auto error_msg = "invalid eth_callBundle hash list: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    SILK_DEBUG << "block_num_or_hash: " << block_num_or_hash << " timeout: " << timeout;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_with_hash = co_await core::read_block_by_block_num_or_hash(*block_cache_, *chain_storage, *tx, block_num_or_hash);
        if (!block_with_hash) {
            reply = make_json_content(request, {});
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        const auto chain_config = co_await chain_storage->read_chain_config();
        const bool is_latest_block = co_await block_reader.get_latest_executed_block_num() == block_with_hash->block.header.number;
        tx->set_state_cache_enabled(/*cache_enabled=*/is_latest_block);

        const auto start_time = clock_time::now();

        struct CallBundleInfo bundle_info {};
        bool error{false};

        silkworm::Bytes hash_data{};

        for (size_t i{0}; i < tx_hash_list.size(); ++i) {
            struct CallBundleTxInfo tx_info {};
            const auto tx_with_block = co_await core::read_transaction_by_hash(*block_cache_, *chain_storage, tx_hash_list[i]);
            if (!tx_with_block) {
                reply = make_json_content(request, {});
                error = true;
                break;
            }

            execution::StateFactory state_factory{*tx};
            const auto txn_id = co_await state_factory.user_txn_id_at(block_with_hash->block.header.number + 1);

            const auto execution_result = co_await EVMExecutor::call(
                chain_config, *chain_storage, workers_, block_with_hash->block, tx_with_block->transaction, txn_id, [&](auto& io_executor, auto curr_txn_id, auto& storage) {
                    return state_factory.create_state(io_executor, storage, curr_txn_id);
                });
            if (execution_result.pre_check_error) {
                reply = make_json_error(request, kServerError, execution_result.pre_check_error.value());
                error = true;
                break;
            }

            if ((clock_time::since(start_time) / 1000000) > timeout) {
                const auto error_msg = "execution aborted (timeout)";
                SILK_ERROR << error_msg;
                reply = make_json_error(request, kServerError, error_msg);
                error = true;
                break;
            }
            tx_info.gas_used = tx_with_block->transaction.gas_limit - execution_result.gas_left;
            tx_info.hash = hash_of_transaction(tx_with_block->transaction);

            if (!execution_result.success()) {
                tx_info.error_message = execution_result.error_message(false /* full_error */);
            } else {
                tx_info.value = silkworm::to_bytes32(execution_result.data);
            }

            bundle_info.txs_info.push_back(tx_info);
            hash_data.append({tx_info.hash.bytes, silkworm::kHashLength});
        }
        if (!error) {
            bundle_info.bundle_hash = hash_of(hash_data);
            reply = make_json_content(request, bundle_info);
        }
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, {});
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_newfilter
Task<void> EthereumRpcApi::handle_eth_new_filter(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_newFilter params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    auto filter = params[0].get<StoredFilter>();
    SILK_DEBUG << "filter: " << filter;

    if ((filter.from_block && filter.from_block.value() == kPendingBlockId) ||
        (filter.to_block && filter.to_block.value() == kPendingBlockId)) {
        reply = make_json_error(request, kInvalidParams, "pending logs not supported");
        co_return;
    }

    auto tx = co_await database_->begin_transaction();

    try {
        auto storage = tx->create_storage();
        LogsWalker logs_walker(*block_cache_, *tx, *storage, *backend_, workers_);

        const auto [start, end] = co_await logs_walker.get_block_nums(filter);
        filter.start = start;
        filter.end = end;

        const auto filter_id = filter_storage_->add_filter(filter);
        SILK_TRACE << "Added a new filter, storage size: " << filter_storage_->size();

        if (filter_id) {
            reply = make_json_content(request, filter_id.value());
        } else {
            reply = make_json_error(request, kServerError, "TODO");
        }
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, {});
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_newblockfilter
Task<void> EthereumRpcApi::handle_eth_new_block_filter(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        reply = make_json_content(request, to_quantity(0));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_newpendingtransactionfilter
Task<void> EthereumRpcApi::handle_eth_new_pending_transaction_filter(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        reply = make_json_content(request, to_quantity(0));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getfilterlogs
Task<void> EthereumRpcApi::handle_eth_get_filter_logs(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getFilterLogs params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    auto filter_id = params[0].get<std::string>();
    SILK_TRACE << "filter_id: " << filter_id;

    const auto filter_ref = filter_storage_->get_filter(filter_id);
    if (!filter_ref) {
        reply = make_json_error(request, kServerError, "filter not found");
        co_return;
    }

    auto& filter = filter_ref->get();

    auto tx = co_await database_->begin_transaction();

    try {
        auto storage = tx->create_storage();
        LogsWalker logs_walker(*block_cache_, *tx, *storage, *backend_, workers_);

        const auto [start, end] = co_await logs_walker.get_block_nums(filter);

        if (filter.start != start && filter.end != end) {
            filter.logs.clear();
            co_await logs_walker.get_logs(start, end, filter.addresses, filter.topics, filter.logs);
        } else {
            co_await logs_walker.get_logs(start, end, filter.addresses, filter.topics, filter.logs);
        }
        filter.start = start;
        filter.end = end;

        reply = make_json_content(request, filter.logs);
    } catch (const std::invalid_argument&) {
        reply = make_json_content(request, {});
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getfilterchanges
Task<void> EthereumRpcApi::handle_eth_get_filter_changes(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getFilterChanges params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    auto filter_id = params[0].get<std::string>();
    SILK_TRACE << "filter_id: " << filter_id;

    const auto filter_opt = filter_storage_->get_filter(filter_id);

    if (!filter_opt) {
        reply = make_json_error(request, kServerError, "filter not found");
        co_return;
    }

    auto& filter = filter_opt.value().get();
    auto tx = co_await database_->begin_transaction();

    try {
        auto storage = tx->create_storage();
        LogsWalker logs_walker(*block_cache_, *tx, *storage, *backend_, workers_);

        const auto [start, end] = co_await logs_walker.get_block_nums(filter);

        std::vector<Log> logs;
        if (filter.start == start && filter.end != end) {
            co_await logs_walker.get_logs(start, end, filter.addresses, filter.topics, logs);
            filter.logs.insert(filter.logs.end(), logs.begin(), logs.end());
        } else if (filter.start != start && filter.end != end) {
            co_await logs_walker.get_logs(start, end, filter.addresses, filter.topics, logs);
            filter.logs.clear();
            filter.logs.insert(filter.logs.end(), logs.begin(), logs.end());
        }
        filter.start = start;
        filter.end = end;

        reply = make_json_content(request, logs);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_uninstallfilter
Task<void> EthereumRpcApi::handle_eth_uninstall_filter(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_uninstallFilter params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    auto filter_id = params[0].get<std::string>();
    SILK_DEBUG << "filter_id: " << filter_id;

    const auto success = filter_storage_->remove_filter(filter_id);

    SILK_TRACE << "Removing filter " << (success ? "succeeded" : "failed") << ", storage size: " << filter_storage_->size();

    reply = make_json_content(request, success);
}

// https://eth.wiki/json-rpc/API#eth_getlogs
Task<void> EthereumRpcApi::handle_eth_get_logs(const nlohmann::json& request, std::string& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILK_ERROR << error_msg << request.dump();
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }
    const auto& params = request["params"];
    if (params.size() > 1) {
        auto error_msg = "too many arguments, want at most 1";
        SILK_ERROR << error_msg << request.dump();
        make_glaze_json_error(request, kInvalidParams, error_msg, reply);
        co_return;
    }

    auto filter = params[0].get<Filter>();
    SILK_DEBUG << "filter: " << filter;

    auto tx = co_await database_->begin_transaction();

    try {
        auto storage = tx->create_storage();
        LogsWalker logs_walker(*block_cache_, *tx, *storage, *backend_, workers_);

        const auto [start, end] = co_await logs_walker.get_block_nums(filter);
        if (start == end && start == std::numeric_limits<std::uint64_t>::max()) {
            auto error_msg = "invalid eth_getLogs filter block_hash: " + filter.block_hash.value();
            SILK_ERROR << error_msg;
            reply = make_json_error(request, 100, error_msg);
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }

        std::vector<Log> logs;
        co_await logs_walker.get_logs(start, end, filter.addresses, filter.topics, logs);

        make_glaze_json_content(request, logs, reply);
    } catch (const std::invalid_argument&) {
        std::vector<silkworm::rpc::Log> log{};
        make_glaze_json_content(request, log, reply);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        make_glaze_json_error(request, kInternalError, e.what(), reply);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        make_glaze_json_error(request, kServerError, "unexpected exception", reply);
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_sendrawtransaction
Task<void> EthereumRpcApi::handle_eth_send_raw_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_sendRawTransaction params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto encoded_tx_string = params[0].get<std::string>();
    const auto encoded_tx_bytes = silkworm::from_hex(encoded_tx_string);
    if (!encoded_tx_bytes.has_value()) {
        const auto error_msg = "invalid eth_sendRawTransaction encoded tx: " + encoded_tx_string;
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    silkworm::ByteView encoded_tx_view{*encoded_tx_bytes};
    Transaction txn;
    const auto decoding_result{silkworm::rlp::decode_transaction(encoded_tx_view, txn, silkworm::rlp::Eip2718Wrapping::kBoth)};
    if (!decoding_result) {
        const auto error_msg = decoding_result_to_string(decoding_result.error());
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    constexpr float kTxFeeCap = 1;  // 1 ether

    if (!check_tx_fee_less_cap(kTxFeeCap, txn.max_fee_per_gas, txn.gas_limit)) {
        const auto error_msg = "tx fee exceeds the configured cap";
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    if (!is_replay_protected(txn)) {
        const auto error_msg = "only replay-protected (EIP-155) transactions allowed over RPC";
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    const silkworm::ByteView encoded_tx{*encoded_tx_bytes};
    const auto result = co_await tx_pool_->add_transaction(encoded_tx);
    if (!result.success) {
        SILK_ERROR << "cannot add transaction: " << result.error_descr;
        reply = make_json_error(request, kServerError, result.error_descr);
        co_return;
    }

    if (!txn.sender()) {
        const auto error_msg = "cannot recover sender";
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    const auto ethash_hash = txn.hash();
    const auto hash = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
    if (!txn.to.has_value()) {
        const auto contract_address = silkworm::create_address(*txn.sender(), txn.nonce);
        SILK_DEBUG << "submitted contract creation hash: " << silkworm::to_hex(hash) << " from: " << *txn.sender() << " nonce: " << txn.nonce << " contract: " << contract_address << " value: " << txn.value;
    } else {
        SILK_DEBUG << "submitted transaction hash: " << silkworm::to_hex(hash) << " from: " << *txn.sender() << " nonce: " << txn.nonce << " recipient: " << *txn.to << " value: " << txn.value;
    }

    reply = make_json_content(request, hash);
}

// https://eth.wiki/json-rpc/API#eth_sendtransaction
Task<void> EthereumRpcApi::handle_eth_send_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        reply = make_json_content(request, to_quantity(0));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_signtransaction
Task<void> EthereumRpcApi::handle_eth_sign_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        reply = make_json_content(request, to_quantity(0));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getproof
Task<void> EthereumRpcApi::handle_eth_get_proof(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        reply = make_json_content(request, to_quantity(0));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_mining
Task<void> EthereumRpcApi::handle_eth_mining(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto mining_result = co_await miner_->get_mining();
        reply = make_json_content(request, mining_result.enabled && mining_result.running);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, kServerError, se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#eth_coinbase
Task<void> EthereumRpcApi::handle_eth_coinbase(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto coinbase_address = co_await backend_->etherbase();
        reply = make_json_content(request, coinbase_address);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, kServerError, se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#eth_hashrate
Task<void> EthereumRpcApi::handle_eth_hashrate(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto hash_rate = co_await miner_->get_hash_rate();
        reply = make_json_content(request, to_quantity(hash_rate));
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, kServerError, se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#eth_submithashrate
Task<void> EthereumRpcApi::handle_eth_submit_hashrate(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        const auto error_msg = "invalid eth_submitHashrate params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    try {
        const auto hash_rate = params[0].get<intx::uint256>();
        const auto id = params[1].get<evmc::bytes32>();
        const auto success = co_await miner_->submit_hash_rate(hash_rate, id);
        reply = make_json_content(request, success);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, kServerError, se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#eth_getwork
Task<void> EthereumRpcApi::handle_eth_get_work(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto work = co_await miner_->get_work();
        const std::vector<std::string> current_work{
            silkworm::to_hex(work.header_hash),
            silkworm::to_hex(work.seed_hash),
            silkworm::to_hex(work.target),
            silkworm::to_hex(work.block_num)};
        reply = make_json_content(request, current_work);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, kServerError, se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#eth_submitwork
Task<void> EthereumRpcApi::handle_eth_submit_work(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        const auto error_msg = "invalid eth_submitWork params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    try {
        const auto block_nonce = silkworm::from_hex(params[0].get<std::string>());
        if (!block_nonce.has_value()) {
            const auto error_msg = "invalid eth_submitWork params: " + params.dump();
            SILK_ERROR << error_msg;
            reply = make_json_error(request, 100, error_msg);
            co_return;
        }
        const auto pow_hash = params[1].get<evmc::bytes32>();
        const auto digest = params[2].get<evmc::bytes32>();
        const auto success = co_await miner_->submit_work(block_nonce.value(), pow_hash, digest);
        reply = make_json_content(request, success);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "error: \"" << se.code().message() << "\" processing request: " << request.dump();
        reply = make_json_error(request, kServerError, se.code().message());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#eth_subscribe
Task<void> EthereumRpcApi::handle_eth_subscribe(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        reply = make_json_content(request, to_quantity(0));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_unsubscribe
Task<void> EthereumRpcApi::handle_eth_unsubscribe(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin_transaction();

    try {
        reply = make_json_content(request, to_quantity(0));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_feehistory
Task<void> EthereumRpcApi::handle_eth_fee_history(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        const auto error_msg = "invalid eth_feeHistory params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }

    uint64_t block_count{0};
    if (params[0].is_string()) {
        const auto value = params[0].get<std::string>();
        size_t processed_characters{0};
        block_count = std::stoul(value, &processed_characters, 16);
        if (processed_characters != value.size()) {
            const auto error_msg = "invalid block_count: " + value;
            SILK_ERROR << error_msg;
            reply = make_json_error(request, 100, error_msg);
            co_return;
        }
    } else {
        block_count = params[0].get<uint64_t>();
    }
    const auto newest_block = params[1].get<std::string>();
    const auto reward_percentiles = params[2].get<std::vector<int8_t>>();

    SILK_TRACE << "block_count: " << block_count << " newest_block: " << newest_block
               << " reward_percentiles size: " << reward_percentiles.size();

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};

        rpc::fee_history::BlockHeaderProvider block_header_provider = [&chain_storage](BlockNum block_num) {
            return chain_storage->read_canonical_header(block_num);
        };
        rpc::fee_history::BlockProvider block_provider = [this, &chain_storage](BlockNum block_num) {
            return core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        };
        rpc::fee_history::ReceiptsProvider receipts_provider = [&tx, &chain_storage, this](const BlockWithHash& block_with_hash) {
            return core::get_receipts(*tx, block_with_hash, *chain_storage, this->workers_);
        };

        rpc::fee_history::LatestBlockProvider latest_block_provider = [&block_reader]() {
            return block_reader.get_block_num(kLatestBlockId);
        };

        const auto chain_config = co_await chain_storage->read_chain_config();
        rpc::fee_history::FeeHistoryOracle oracle{chain_config, block_header_provider, block_provider, receipts_provider, latest_block_provider};

        const auto block_num = co_await block_reader.get_block_num(newest_block);
        const auto fee_history = co_await oracle.fee_history(block_num, block_count, reward_percentiles);

        if (fee_history.error) {
            reply = make_json_error(request, kServerError, fee_history.error.value());
        } else {
            reply = make_json_content(request, fee_history);
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<void> EthereumRpcApi::handle_eth_base_fee(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (!params.empty()) {
        const auto error_msg = "invalid eth_baseFee params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }

    auto tx = co_await database_->begin_transaction();

    try {
        intx::uint256 base_fee{0};
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto chain_config = co_await chain_storage->read_chain_config();
        const auto latest_block_num = co_await block_reader.get_block_num(kLatestBlockId);
        const auto latest_block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, latest_block_num);
        if (!latest_block_with_hash) {
            reply = make_json_content(request, to_quantity(base_fee));
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        auto& header = latest_block_with_hash->block.header;

        if (chain_config.is_london(header.number + 1)) {
            base_fee = protocol::expected_base_fee_per_gas(header);
        } else {
            base_fee = 0;
        }

        reply = make_json_content(request, to_quantity(base_fee));

    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<void> EthereumRpcApi::handle_eth_blob_base_fee(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (!params.empty()) {
        const auto error_msg = "invalid eth_blobBaseFee params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }

    auto tx = co_await database_->begin_transaction();

    try {
        intx::uint256 blob_base_fee{0};
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto latest_block_num = co_await block_reader.get_block_num(kLatestBlockId);
        const auto latest_block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, latest_block_num);
        if (!latest_block_with_hash) {
            reply = make_json_content(request, to_quantity(blob_base_fee));
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        auto& header = latest_block_with_hash->block.header;

        if (header.excess_blob_gas) {
            blob_base_fee = calc_blob_gas_price(protocol::calc_excess_blob_gas(header));
        } else {
            blob_base_fee = 0;
        }
        reply = make_json_content(request, to_quantity(blob_base_fee));

    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

// https://eth.wiki/json-rpc/API#eth_getblockreceipts
Task<void> EthereumRpcApi::handle_eth_get_block_receipts(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid eth_getBlockReceipts params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num_or_hash = BlockNumOrHash{block_id};
        const auto block_num = co_await block_reader.get_block_num(block_num_or_hash);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num.first);
        if (block_with_hash) {
            auto receipts{co_await core::get_receipts(*tx, *block_with_hash, *chain_storage, workers_)};
            SILK_TRACE << "#receipts: " << receipts.size();

            const auto block{block_with_hash->block};
            if (receipts.size() == block.transactions.size()) {
                for (size_t i{0}; i < block.transactions.size(); ++i) {
                    receipts[i].effective_gas_price = block.transactions[i].effective_gas_price(block.header.base_fee_per_gas.value_or(0));
                }
                reply = make_json_content(request, receipts);
            } else {
                reply = make_json_content(request, {});
            }
        } else {
            reply = make_json_content(request, {});
        }
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, {});
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

}  // namespace silkworm::rpc::commands
