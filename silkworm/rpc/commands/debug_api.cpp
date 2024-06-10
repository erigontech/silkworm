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

#include "debug_api.hpp"

#include <algorithm>
#include <ostream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/async_task.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/account_dumper.hpp>
#include <silkworm/rpc/core/blocks.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/evm_debug.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/core/rawdb/chain.hpp>
#include <silkworm/rpc/core/storage_walker.hpp>
#include <silkworm/rpc/ethdb/walk.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/call.hpp>
#include <silkworm/rpc/types/dump_account.hpp>

namespace silkworm::rpc::commands {

static constexpr int16_t kAccountRangeMaxResults{256};

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_accountrange
Task<void> DebugRpcApi::handle_debug_account_range(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 5) {
        auto error_msg = "invalid debug_accountRange params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    const auto block_number_or_hash = params[0].get<BlockNumberOrHash>();
    const auto start_key_array = params[1].get<std::vector<std::uint8_t>>();
    auto max_result = params[2].get<int16_t>();
    const auto exclude_code = params[3].get<bool>();
    const auto exclude_storage = params[4].get<bool>();

    silkworm::Bytes start_key(start_key_array.data(), start_key_array.size());
    const auto start_address = bytes_to_address(start_key);

    if (max_result > kAccountRangeMaxResults || max_result <= 0) {
        max_result = kAccountRangeMaxResults;
    }

    SILK_TRACE << "block_number_or_hash: " << block_number_or_hash
               << " start_address: " << start_address
               << " max_result: " << max_result
               << " exclude_code: " << exclude_code
               << " exclude_storage: " << exclude_storage;

    auto tx = co_await database_->begin();

    try {
        auto start = std::chrono::system_clock::now();
        core::AccountDumper dumper{*tx};
        DumpAccounts dump_accounts = co_await dumper.dump_accounts(*block_cache_, block_number_or_hash, backend_, start_address, max_result, exclude_code, exclude_storage);
        auto end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        SILK_DEBUG << "dump_accounts: elapsed " << elapsed_seconds.count() << " sec";

        reply = make_json_content(request, dump_accounts);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_getmodifiedaccountsbynumber
Task<void> DebugRpcApi::handle_debug_get_modified_accounts_by_number(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty() || params.size() > 2) {
        auto error_msg = "invalid debug_getModifiedAccountsByNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }

    auto start_block_id = params[0].get<std::string>();
    auto end_block_id = start_block_id;
    if (params.size() == 2) {
        end_block_id = params[1].get<std::string>();
    }
    SILK_DEBUG << "start_block_id: " << start_block_id << " end_block_id: " << end_block_id;

    auto tx = co_await database_->begin();

    try {
        const auto start_block_number = co_await core::get_block_number(start_block_id, *tx);
        const auto end_block_number = co_await core::get_block_number(end_block_id, *tx);

        const auto addresses = co_await get_modified_accounts(*tx, start_block_number, end_block_number);
        reply = make_json_content(request, addresses);
    } catch (const std::invalid_argument& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, -32000, e.what());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_getmodifiedaccountsbyhash
Task<void> DebugRpcApi::handle_debug_get_modified_accounts_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty() || params.size() > 2) {
        auto error_msg = "invalid debug_getModifiedAccountsByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }

    auto start_hash = params[0].get<evmc::bytes32>();
    auto end_hash = start_hash;
    if (params.size() == 2) {
        end_hash = params[1].get<evmc::bytes32>();
    }
    SILK_DEBUG << "start_hash: " << silkworm::to_hex(start_hash) << " end_hash: " << silkworm::to_hex(end_hash);

    auto tx = co_await database_->begin();

    try {
        const auto start_block_number = co_await core::rawdb::read_header_number(*tx, start_hash);
        const auto end_block_number = co_await core::rawdb::read_header_number(*tx, end_hash);
        auto addresses = co_await get_modified_accounts(*tx, start_block_number, end_block_number);
        reply = make_json_content(request, addresses);
    } catch (const std::invalid_argument& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, -32000, e.what());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_storagerangeat
Task<void> DebugRpcApi::handle_debug_storage_range_at(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty() || params.size() > 5) {
        auto error_msg = "invalid debug_storageRangeAt params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }

    auto block_hash = params[0].get<evmc::bytes32>();
    auto tx_index = params[1].get<std::uint64_t>();
    auto address = params[2].get<evmc::address>();
    auto start_key = params[3].get<evmc::bytes32>();
    auto max_result = params[4].get<std::uint64_t>();

    SILK_DEBUG << "block_hash: 0x" << silkworm::to_hex(block_hash)
               << " tx_index: " << tx_index
               << " address: " << address
               << " start_key: 0x" << silkworm::to_hex(start_key)
               << " max_result: " << max_result;

    auto tx = co_await database_->begin();

    try {
        const auto chain_storage = tx->create_storage(backend_);

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (!block_with_hash) {
            SILK_WARN << "debug_storage_range_at: block not found, hash: " << evmc::hex(block_hash);
            nlohmann::json result = {{"storage", nullptr}, {"nextKey", nullptr}};
            reply = make_json_content(request, result);

            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }

        auto block_number = block_with_hash->block.header.number - 1;

        nlohmann::json storage({});
        silkworm::Bytes next_key;
        std::uint16_t count{0};

        StorageWalker::StorageCollector collector = [&](const silkworm::ByteView key, silkworm::ByteView sec_key, silkworm::ByteView value) {
            SILK_TRACE << "StorageCollector: suitable for result"
                       << " key: 0x" << silkworm::to_hex(key)
                       << " sec_key: 0x" << silkworm::to_hex(sec_key)
                       << " value: " << silkworm::to_hex(value);

            auto val = silkworm::to_hex(value);
            val.insert(0, 64 - val.length(), '0');
            if (count < max_result) {
                storage["0x" + silkworm::to_hex(sec_key)] = {{"key", "0x" + silkworm::to_hex(key)}, {"value", "0x" + val}};
            } else {
                next_key = key;
            }

            return count++ < max_result;
        };
        StorageWalker storage_walker{*tx};
        co_await storage_walker.storage_range_at(block_number, address, start_key, max_result, collector);

        nlohmann::json result = {{"storage", storage}};
        if (next_key.empty()) {
            result["nextKey"] = nlohmann::json();
        } else {
            result["nextKey"] = "0x" + silkworm::to_hex(next_key);
        }

        reply = make_json_content(request, result);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debugdebugaccountat
Task<void> DebugRpcApi::handle_debug_account_at(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty() || params.size() < 3) {
        auto error_msg = "invalid debug_accountAt params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }

    auto block_hash = params[0].get<evmc::bytes32>();
    auto tx_index = params[1].get<uint64_t>();
    auto address = params[2].get<evmc::address>();

    SILK_DEBUG << "block_hash: 0x" << silkworm::to_hex(block_hash)
               << " tx_index: " << tx_index
               << " address: " << address;

    auto tx = co_await database_->begin();

    try {
        const auto chain_storage = tx->create_storage(backend_);

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (!block_with_hash) {
            const std::string error_msg = "block not found ";
            SILK_TRACE << "handle_debug_account_at: core::read_block_by_hash: " << error_msg << request.dump();
            reply = make_json_error(request, -32000, error_msg);
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }

        const auto& block = block_with_hash->block;
        auto block_number = block.header.number;
        const auto& transactions = block.transactions;

        SILK_TRACE << "Block number: " << block_number << " #tnx: " << transactions.size();

        auto chain_config_ptr = co_await chain_storage->read_chain_config();
        ensure(chain_config_ptr.has_value(), "cannot read chain config");

        auto this_executor = co_await boost::asio::this_coro::executor;
        auto result = co_await async_task(workers_.executor(), [&]() -> nlohmann::json {
            auto state = tx->create_state(this_executor, *chain_storage, block_number - 1);
            auto account_opt = state->read_account(address);
            account_opt.value_or(silkworm::Account{});

            EVMExecutor executor{*chain_config_ptr, workers_, state};

            uint64_t index = std::min(static_cast<uint64_t>(transactions.size()), tx_index);
            for (uint64_t idx{0}; idx < index; idx++) {
                rpc::Transaction txn{transactions[idx]};
                executor.call(block, txn);
            }

            const auto& ibs = executor.get_ibs_state();

            nlohmann::json json_result;
            if (ibs.exists(address)) {
                std::ostringstream oss;
                oss << std::hex << ibs.get_nonce(address);
                json_result["nonce"] = "0x" + oss.str();
                json_result["balance"] = "0x" + intx::to_string(ibs.get_balance(address), 16);
                json_result["codeHash"] = ibs.get_code_hash(address);
                json_result["code"] = "0x" + silkworm::to_hex(ibs.get_code(address));
            } else {
                json_result["balance"] = "0x0";
                json_result["code"] = "0x";
                json_result["codeHash"] = "0x0000000000000000000000000000000000000000000000000000000000000000";
                json_result["nonce"] = "0x0";
            }
            return json_result;
        });

        reply = make_json_content(request, result);
    } catch (const std::invalid_argument& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, -32000, e.what());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_tracetransaction
Task<void> DebugRpcApi::handle_debug_trace_transaction(const nlohmann::json& request, json::Stream& stream) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid debug_traceTransaction params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request, 100, error_msg);
        stream.write_json(reply);

        co_return;
    }
    auto transaction_hash = params[0].get<evmc::bytes32>();

    debug::DebugConfig config;
    if (params.size() > 1) {
        config = params[1].get<debug::DebugConfig>();
    }

    SILK_DEBUG << "transaction_hash: " << silkworm::to_hex(transaction_hash) << " config: {" << config << "}";

    stream.open_object();
    stream.write_json_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        debug::DebugExecutor executor{*block_cache_, workers_, *tx, config};
        const auto chain_storage = tx->create_storage(backend_);
        co_await executor.trace_transaction(stream, *chain_storage, transaction_hash);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        const Error error{100, e.what()};
        stream.write_json_field("error", error);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_json_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_tracecall
Task<void> DebugRpcApi::handle_debug_trace_call(const nlohmann::json& request, json::Stream& stream) {
    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid debug_traceCall params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request, 100, error_msg);
        stream.write_json(reply);

        co_return;
    }
    const auto call = params[0].get<Call>();
    const auto block_number_or_hash = params[1].get<BlockNumberOrHash>();
    debug::DebugConfig config;
    if (params.size() > 2) {
        config = params[2].get<debug::DebugConfig>();
    }

    SILK_DEBUG << "call: " << call << " block_number_or_hash: " << block_number_or_hash << " config: {" << config << "}";

    stream.open_object();
    stream.write_json_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        const auto chain_storage = tx->create_storage(backend_);

        const bool is_latest_block = co_await core::is_latest_block_number(block_number_or_hash, *tx);
        tx->set_state_cache_enabled(/*cache_enabled=*/is_latest_block);

        debug::DebugExecutor executor{*block_cache_, workers_, *tx, config};
        co_await executor.trace_call(stream, block_number_or_hash, *chain_storage, call);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        std::ostringstream oss;
        oss << "block " << block_number_or_hash.number() << "(" << silkworm::to_hex(block_number_or_hash.hash()) << ") not found";
        const Error error{-32000, oss.str()};
        stream.write_json_field("error", error);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_json_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_tracecallmany
Task<void> DebugRpcApi::handle_debug_trace_call_many(const nlohmann::json& request, json::Stream& stream) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required arguments";
        SILK_ERROR << error_msg << request.dump();
        const auto reply = make_json_error(request, 100, error_msg);
        stream.write_json(reply);

        co_return;
    }

    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid debug_traceCallMany params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request, 100, error_msg);
        stream.write_json(reply);

        co_return;
    }
    const auto bundles = params[0].get<Bundles>();

    if (bundles.empty()) {
        const auto error_msg = "invalid debug_traceCallMany bundle list: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request, 100, error_msg);
        stream.write_json(reply);

        co_return;
    }

    const auto simulation_context = params[1].get<SimulationContext>();

    debug::DebugConfig config;
    if (params.size() > 2) {
        config = params[2].get<debug::DebugConfig>();
    }

    SILK_DEBUG << "bundles: " << bundles << " simulation_context: " << simulation_context << " config: {" << config << "}";

    stream.open_object();
    stream.write_json_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        debug::DebugExecutor executor{*block_cache_, workers_, *tx, config};
        const auto chain_storage = tx->create_storage(backend_);
        co_await executor.trace_call_many(stream, *chain_storage, bundles, simulation_context);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_json_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_traceblockbynumber
Task<void> DebugRpcApi::handle_debug_trace_block_by_number(const nlohmann::json& request, json::Stream& stream) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid debug_traceBlockByNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request, 100, error_msg);
        stream.write_json(reply);
        co_return;
    }
    BlockNum block_number{0};
    if (params[0].is_string()) {
        block_number = std::stoul(params[0].get<std::string>(), nullptr, 10);
    } else {
        block_number = params[0].get<BlockNum>();
    }

    debug::DebugConfig config;
    if (params.size() > 1) {
        config = params[1].get<debug::DebugConfig>();
    }

    SILK_DEBUG << "block_number: " << block_number << " config: {" << config << "}";

    stream.open_object();
    stream.write_json_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        const auto chain_storage = tx->create_storage(backend_);

        debug::DebugExecutor executor{*block_cache_, workers_, *tx, config};
        co_await executor.trace_block(stream, *chain_storage, block_number);
    } catch (const std::invalid_argument& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        std::ostringstream oss;
        oss << "block_number " << block_number << " not found";
        const Error error{-32000, oss.str()};
        stream.write_json_field("error", error);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        const Error error{100, e.what()};
        stream.write_json_field("error", error);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_json_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_traceblockbyhash
Task<void> DebugRpcApi::handle_debug_trace_block_by_hash(const nlohmann::json& request, json::Stream& stream) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid debug_traceBlockByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request, 100, error_msg);
        stream.write_json(reply);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();

    debug::DebugConfig config;
    if (params.size() > 1) {
        config = params[1].get<debug::DebugConfig>();
    }

    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash) << " config: {" << config << "}";

    stream.open_object();
    stream.write_json_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        const auto chain_storage = tx->create_storage(backend_);

        debug::DebugExecutor executor{*block_cache_, workers_, *tx, config};
        co_await executor.trace_block(stream, *chain_storage, block_hash);
    } catch (const std::invalid_argument& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        std::ostringstream oss;
        oss << "block_hash " << silkworm::to_hex(block_hash) << " not found";
        const Error error{-32000, oss.str()};
        stream.write_json_field("error", error);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        const Error error{100, e.what()};
        stream.write_json_field("error", error);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_json_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

Task<std::set<evmc::address>> get_modified_accounts(ethdb::Transaction& tx, BlockNum start_block_number, BlockNum end_block_number) {
    const auto latest_block_number = co_await core::get_block_number(core::kLatestBlockId, tx);

    SILK_DEBUG << "latest: " << latest_block_number << " start: " << start_block_number << " end: " << end_block_number;

    std::set<evmc::address> addresses;
    if (start_block_number > latest_block_number) {
        std::stringstream msg;
        msg << "start block (" << start_block_number << ") is later than the latest block (" << latest_block_number << ")";
        throw std::invalid_argument(msg.str());
    } else if (start_block_number <= end_block_number) {
        auto walker = [&](const silkworm::Bytes& key, const silkworm::Bytes& value) {
            auto block_number = static_cast<BlockNum>(std::stol(silkworm::to_hex(key), nullptr, 16));
            if (block_number <= end_block_number) {
                auto address = bytes_to_address(value.substr(0, kAddressLength));

                SILK_TRACE << "Walker: processing block " << block_number << " address " << address;
                addresses.insert(address);
            }
            return block_number <= end_block_number;
        };

        const auto key = silkworm::db::block_key(start_block_number);
        SILK_TRACE << "Ready to walk starting from key: " << silkworm::to_hex(key);

        co_await walk(tx, db::table::kAccountChangeSetName, key, 0, walker);
    }

    co_return addresses;
}

Task<void> DebugRpcApi::handle_debug_get_raw_block(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];

    if (params.size() != 1) {
        auto error_msg = "invalid debug_getRawBlock params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin();

    try {
        const auto chain_storage = tx->create_storage(backend_);
        const auto block_number = co_await core::get_block_number(block_id, *tx);
        silkworm::Block block;
        if (!(co_await chain_storage->read_canonical_block(block_number, block))) {
            throw std::invalid_argument("block not found");
        }
        Bytes encoded_block;
        rlp::encode(encoded_block, block);
        reply = make_json_content(request, silkworm::to_hex(encoded_block, true));
    } catch (const std::invalid_argument& iv) {
        SILK_ERROR << "exception: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_error(request, -32602, iv.what());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

Task<void> DebugRpcApi::handle_debug_get_raw_header(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid debug_getRawHeader params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin();

    try {
        const auto chain_storage = tx->create_storage(backend_);
        const auto block_number = co_await core::get_block_number(block_id, *tx);
        const auto block_hash = co_await chain_storage->read_canonical_hash(block_number);
        auto header = co_await chain_storage->read_header(block_number, block_hash->bytes);
        if (!header) {
            throw std::invalid_argument("header not found");
        }
        Bytes encoded_header;
        rlp::encode(encoded_header, *header);
        reply = make_json_content(request, silkworm::to_hex(encoded_header, true));
    } catch (const std::invalid_argument& iv) {
        SILK_ERROR << "exception: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_error(request, -32602, iv.what());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

Task<void> DebugRpcApi::handle_debug_get_raw_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid debug_getRawTransaction params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    auto transaction_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "transaction_hash: " << silkworm::to_hex(transaction_hash);

    auto tx = co_await database_->begin();

    try {
        const auto chain_storage{tx->create_storage(backend_)};

        Bytes rlp{};
        auto success = co_await chain_storage->read_rlp_transaction(transaction_hash, rlp);
        if (!success) {
            throw std::invalid_argument("transaction not found");
        }
        reply = make_json_content(request, silkworm::to_hex(rlp, true));
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_error(request, -32602, iv.what());
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

}  // namespace silkworm::rpc::commands
