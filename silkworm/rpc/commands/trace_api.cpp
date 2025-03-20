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

#include "trace_api.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/compatibility.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/evm_trace.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>
#include <silkworm/rpc/types/call.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#trace_call
Task<void> TraceRpcApi::handle_trace_call(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() < 3) {
        auto error_msg = "invalid trace_call params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto call = params[0].get<Call>();
    const auto config = params[1].get<trace::TraceConfig>();
    const auto block_num_or_hash = params[2].get<BlockNumOrHash>();

    SILK_TRACE << "call: " << call << " block_num_or_hash: " << block_num_or_hash << " config: " << config;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        const BlockReader block_reader{*chain_storage, *tx};

        const auto block_with_hash = co_await core::read_block_by_block_num_or_hash(*block_cache_, *chain_storage, *tx, block_num_or_hash);
        if (!block_with_hash) {
            reply = make_json_error(request, 100, "block not found");
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        const bool is_latest_block = co_await block_reader.is_latest_block_num(block_with_hash->block.header.number);

        trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};
        const auto result = co_await executor.trace_call(block_with_hash->block, call, config, is_latest_block);

        if (result.pre_check_error) {
            reply = make_json_error(request, kServerError, result.pre_check_error.value());
        } else {
            reply = make_json_content(request, result.traces);
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#trace_callmany
Task<void> TraceRpcApi::handle_trace_call_many(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid trace_callMany params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto trace_calls = params[0].get<std::vector<trace::TraceCall>>();
    const auto block_num_or_hash = params[1].get<BlockNumOrHash>();

    SILK_TRACE << "#trace_calls: " << trace_calls.size() << " block_num_or_hash: " << block_num_or_hash;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        const BlockReader block_reader{*chain_storage, *tx};

        const auto block_with_hash = co_await core::read_block_by_block_num_or_hash(*block_cache_, *chain_storage, *tx, block_num_or_hash);
        if (!block_with_hash) {
            reply = make_json_error(request, kInvalidParams, "block not found");
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        const bool is_latest_block = co_await block_reader.is_latest_block_num(block_with_hash->block.header.number);

        trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};
        const auto result = co_await executor.trace_calls(block_with_hash->block, trace_calls, is_latest_block);

        if (result.pre_check_error) {
            reply = make_json_error(request, kServerError, result.pre_check_error.value());
        } else {
            reply = make_json_content(request, result.traces);
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#trace_rawtransaction
Task<void> TraceRpcApi::handle_trace_raw_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() < 2) {
        const auto error_msg = "invalid trace_rawTransaction params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto encoded_tx_string = params[0].get<std::string>();
    const auto encoded_tx_bytes = silkworm::from_hex(encoded_tx_string);
    if (!encoded_tx_bytes.has_value()) {
        const auto error_msg = "invalid trace_rawTransaction encoded tx: " + encoded_tx_string;
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    silkworm::ByteView encoded_tx_view{*encoded_tx_bytes};
    Transaction transaction;
    const auto decoding_result{silkworm::rlp::decode(encoded_tx_view, transaction)};
    if (!decoding_result) {
        const auto error_msg = decoding_result_to_string(decoding_result.error());
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    constexpr float kTxFeeCap = 1;  // 1 ether

    if (!check_tx_fee_less_cap(kTxFeeCap, transaction.max_fee_per_gas, transaction.gas_limit)) {
        const auto error_msg = "tx fee exceeds the configured cap";
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    if (!is_replay_protected(transaction)) {
        const auto error_msg = "only replay-protected (EIP-155) transactions allowed over RPC";
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    if (!transaction.sender()) {
        const auto error_msg = "cannot recover sender";
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    const auto config = params[1].get<trace::TraceConfig>();

    SILK_TRACE << "transaction: " << transaction << " config: " << config;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        const BlockReader block_reader{*chain_storage, *tx};  // always at latest block

        const auto block_num = co_await block_reader.get_latest_block_num();
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (!block_with_hash) {
            reply = make_json_error(request, kInvalidParams, "block not found");
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }

        trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};
        const auto result = co_await executor.trace_transaction(block_with_hash->block, transaction, config);

        if (result.pre_check_error) {
            reply = make_json_error(request, kServerError, result.pre_check_error.value());
        } else {
            reply = make_json_content(request, result.traces);
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#trace_replayblocktransactions
Task<void> TraceRpcApi::handle_trace_replay_block_transactions(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid trace_replayBlockTransactions params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_num_or_hash = params[0].get<BlockNumOrHash>();
    const auto config = params[1].get<trace::TraceConfig>();

    SILK_TRACE << " block_num_or_hash: " << block_num_or_hash << " config: " << config;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        const auto block_with_hash = co_await core::read_block_by_block_num_or_hash(*block_cache_, *chain_storage, *tx, block_num_or_hash);
        if (block_with_hash) {
            const BlockReader block_reader{*chain_storage, *tx};
            const bool is_latest_block = co_await block_reader.is_latest_block_num(block_with_hash->block.header.number);

            trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};
            const auto result = co_await executor.trace_block_transactions(block_with_hash->block, config, is_latest_block);
            reply = make_json_content(request, result);
        } else {
            reply = make_json_error(request, kInvalidParams, "block not found");
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#trace_replaytransaction
Task<void> TraceRpcApi::handle_trace_replay_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid trace_replayTransaction params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto transaction_hash = params[0].get<evmc::bytes32>();
    const auto config = params[1].get<trace::TraceConfig>();

    SILK_TRACE << "transaction_hash: " << silkworm::to_hex(transaction_hash) << " config: " << config;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        const auto tx_with_block = co_await core::read_transaction_by_hash(*block_cache_, *chain_storage, transaction_hash);
        if (!tx_with_block) {
            std::ostringstream oss;
            oss << "transaction " << silkworm::to_hex(transaction_hash, true) << " not found";
            reply = make_json_error(request, kServerError, oss.str());
        } else {
            trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};
            const auto result = co_await executor.trace_transaction(tx_with_block->block_with_hash->block, tx_with_block->transaction, config);

            if (result.pre_check_error) {
                reply = make_json_error(request, kServerError, result.pre_check_error.value());
            } else {
                reply = make_json_content(request, result.traces);
            }
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#trace_block
Task<void> TraceRpcApi::handle_trace_block(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid trace_block params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_num_or_hash = params[0].get<BlockNumOrHash>();

    SILK_TRACE << " block_num_or_hash: " << block_num_or_hash;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        const auto block_with_hash = co_await core::read_block_by_block_num_or_hash(*block_cache_, *chain_storage, *tx, block_num_or_hash);
        if (!block_with_hash) {
            reply = make_json_error(request, kInvalidParams, "block not found");
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        const BlockReader block_reader{*chain_storage, *tx};
        const bool is_latest_block = co_await block_reader.is_latest_block_num(block_with_hash->block.header.number);

        trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};
        trace::Filter filter;
        const auto result = co_await executor.trace_block(*block_with_hash, filter, nullptr /* json::Stream */, is_latest_block);
        reply = make_json_content(request, result);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#trace_filter
Task<void> TraceRpcApi::handle_trace_filter(const nlohmann::json& request, json::Stream& stream) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid trace_filter params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request, kInvalidParams, error_msg);
        stream.write_json(reply);
        co_return;
    }

    const auto trace_filter = params[0].get<trace::TraceFilter>();

    SILK_TRACE << "trace_filter: " << trace_filter;

    stream.open_object();
    stream.write_json_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();

        trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};

        co_await executor.trace_filter(trace_filter, *chain_storage, stream);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();

        const Error error{kInternalError, e.what()};
        stream.write_json_field("error", error);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();

        const Error error{kServerError, "unexpected exception"};
        stream.write_json_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#trace_get
Task<void> TraceRpcApi::handle_trace_get(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid trace_get params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto transaction_hash = params[0].get<evmc::bytes32>();
    const auto str_indices = params[1].get<std::vector<std::string>>();

    std::vector<uint16_t> indices;
    std::transform(str_indices.begin(), str_indices.end(), std::back_inserter(indices),
                   [](const std::string& str) { return std::stoi(str, nullptr, 16); });
    SILK_TRACE << "transaction_hash: " << silkworm::to_hex(transaction_hash) << ", #indices: " << indices.size();

    // Erigon RpcDaemon compatibility
    // Parity fails if it gets more than a single index. It returns nothing in this case. Must we?
    if (indices.size() > 1) {
        reply = make_json_content(request);
        co_return;
    }

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();

        const auto tx_with_block = co_await core::read_transaction_by_hash(*block_cache_, *chain_storage, transaction_hash);
        if (!tx_with_block) {
            reply = make_json_content(request);
        } else {
            trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};
            const auto result = co_await executor.trace_transaction(*(tx_with_block->block_with_hash), tx_with_block->transaction, /* gas_bailout */ false);

            uint16_t index = indices[0];
            if (rpc::compatibility::is_erigon_json_api_compatibility_required()) {
                index = index + 1;  // Erigon RpcDaemon compatibility
            }
            if (result.size() > index) {
                reply = make_json_content(request, result[index]);
            } else {
                reply = make_json_content(request);
            }
        }
    } catch (const std::exception&) {
        reply = make_json_content(request);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#trace_transaction
Task<void> TraceRpcApi::handle_trace_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid trace_transaction params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto transaction_hash = params[0].get<evmc::bytes32>();

    SILK_TRACE << "transaction_hash: " << silkworm::to_hex(transaction_hash);

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        const auto tx_with_block = co_await core::read_transaction_by_hash(*block_cache_, *chain_storage, transaction_hash);
        if (!tx_with_block) {
            reply = make_json_content(request);
        } else {
            trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};
            auto result = co_await executor.trace_transaction(*(tx_with_block->block_with_hash), tx_with_block->transaction, /* gas_bailout */ false);
            reply = make_json_content(request, result);
        }
    } catch (const std::exception&) {
        reply = make_json_content(request);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

}  // namespace silkworm::rpc::commands
