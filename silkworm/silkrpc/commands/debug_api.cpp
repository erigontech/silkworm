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

#include <chrono>
#include <ostream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/db/util.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/account_dumper.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/evm_debug.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/core/state_reader.hpp>
#include <silkworm/silkrpc/core/storage_walker.hpp>
#include <silkworm/silkrpc/ethdb/kv/cached_database.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/json/call.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/dump_account.hpp>

namespace silkworm::rpc::commands {

static constexpr int16_t kAccountRangeMaxResults{256};

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_accountrange
awaitable<void> DebugRpcApi::handle_debug_account_range(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 5) {
        auto error_msg = "invalid debug_accountRange params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_number_or_hash = params[0].get<BlockNumberOrHash>();
    const auto start_key_array = params[1].get<std::vector<std::uint8_t>>();
    auto max_result = params[2].get<int16_t>();
    const auto exclude_code = params[3].get<bool>();
    const auto exclude_storage = params[4].get<bool>();

    silkworm::Bytes start_key(start_key_array.data(), start_key_array.size());
    const auto start_address = silkworm::to_evmc_address(start_key);

    if (max_result > kAccountRangeMaxResults || max_result <= 0) {
        max_result = kAccountRangeMaxResults;
    }

    SILK_INFO << "block_number_or_hash: " << block_number_or_hash
              << " start_address: 0x" << silkworm::to_hex(start_address)
              << " max_result: " << max_result
              << " exclude_code: " << exclude_code
              << " exclude_storage: " << exclude_storage;

    auto tx = co_await database_->begin();

    try {
        auto start = std::chrono::system_clock::now();
        core::AccountDumper dumper{*tx};
        DumpAccounts dump_accounts = co_await dumper.dump_accounts(*block_cache_, block_number_or_hash, start_address, max_result, exclude_code, exclude_storage);
        auto end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        SILK_DEBUG << "dump_accounts: elapsed " << elapsed_seconds.count() << " sec";

        reply = make_json_content(request["id"], dump_accounts);
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

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_getmodifiedaccountsbynumber
awaitable<void> DebugRpcApi::handle_debug_get_modified_accounts_by_number(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty() || params.size() > 2) {
        auto error_msg = "invalid debug_getModifiedAccountsByNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
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
        ethdb::TransactionDatabase tx_database{*tx};
        const auto start_block_number = co_await core::get_block_number(start_block_id, tx_database);
        const auto end_block_number = co_await core::get_block_number(end_block_id, tx_database);

        const auto addresses = co_await get_modified_accounts(tx_database, start_block_number, end_block_number);
        reply = make_json_content(request["id"], addresses);
    } catch (const std::invalid_argument& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], -32000, e.what());
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

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_getmodifiedaccountsbyhash
awaitable<void> DebugRpcApi::handle_debug_get_modified_accounts_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty() || params.size() > 2) {
        auto error_msg = "invalid debug_getModifiedAccountsByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    auto start_hash = params[0].get<evmc::bytes32>();
    auto end_hash = start_hash;
    if (params.size() == 2) {
        end_hash = params[1].get<evmc::bytes32>();
    }
    SILK_DEBUG << "start_hash: " << start_hash << " end_hash: " << end_hash;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto start_block_number = co_await core::rawdb::read_header_number(tx_database, start_hash);
        const auto end_block_number = co_await core::rawdb::read_header_number(tx_database, end_hash);
        auto addresses = co_await get_modified_accounts(tx_database, start_block_number, end_block_number);
        reply = make_json_content(request["id"], addresses);
    } catch (const std::invalid_argument& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], -32000, e.what());
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

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_storagerangeat
awaitable<void> DebugRpcApi::handle_debug_storage_range_at(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty() || params.size() > 5) {
        auto error_msg = "invalid debug_storageRangeAt params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    auto block_hash = params[0].get<evmc::bytes32>();
    auto tx_index = params[1].get<std::uint64_t>();
    auto address = params[2].get<evmc::address>();
    auto start_key = params[3].get<evmc::bytes32>();
    auto max_result = params[4].get<std::uint64_t>();

    SILK_DEBUG << "block_hash: 0x" << silkworm::to_hex(block_hash)
               << " tx_index: " << tx_index
               << " address: 0x" << silkworm::to_hex(address)
               << " start_key: 0x" << silkworm::to_hex(start_key)
               << " max_result: " << max_result;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);
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
        if (next_key.length() > 0) {
            result["nextKey"] = "0x" + silkworm::to_hex(next_key);
        } else {
            result["nextKey"] = nlohmann::json();
        }

        reply = make_json_content(request["id"], result);
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

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_tracetransaction
awaitable<void> DebugRpcApi::handle_debug_trace_transaction(const nlohmann::json& request, json::Stream& stream) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid debug_traceTransaction params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request["id"], 100, error_msg);
        stream.write_json(reply);

        co_return;
    }
    auto transaction_hash = params[0].get<evmc::bytes32>();

    debug::DebugConfig config;
    if (params.size() > 1) {
        config = params[1].get<debug::DebugConfig>();
    }

    SILK_DEBUG << "transaction_hash: " << transaction_hash << " config: {" << config << "}";

    stream.open_object();
    stream.write_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        debug::DebugExecutor executor{tx_database, *block_cache_, workers_, *tx, config};
        co_await executor.trace_transaction(stream, transaction_hash);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        const Error error{100, e.what()};
        stream.write_field("error", error);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_tracecall
awaitable<void> DebugRpcApi::handle_debug_trace_call(const nlohmann::json& request, json::Stream& stream) {
    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid debug_traceCall params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request["id"], 100, error_msg);
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
    stream.write_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        ethdb::kv::CachedDatabase cached_database{block_number_or_hash, *tx, *state_cache_};

        const bool is_latest_block = co_await core::is_latest_block_number(block_number_or_hash, tx_database);
        const core::rawdb::DatabaseReader& db_reader =
            is_latest_block ? static_cast<core::rawdb::DatabaseReader&>(cached_database) : static_cast<core::rawdb::DatabaseReader&>(tx_database);

        debug::DebugExecutor executor{db_reader, *block_cache_, workers_, *tx, config};
        co_await executor.trace_call(stream, block_number_or_hash, call);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        std::ostringstream oss;
        oss << "block " << block_number_or_hash.number() << "(" << block_number_or_hash.hash() << ") not found";
        const Error error{-32000, oss.str()};
        stream.write_field("error", error);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_tracecallmany
awaitable<void> DebugRpcApi::handle_debug_trace_call_many(const nlohmann::json& request, json::Stream& stream) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required arguments";
        SILK_ERROR << error_msg << request.dump();
        const auto reply = make_json_error(request["id"], 100, error_msg);
        stream.write_json(reply);

        co_return;
    }

    const auto& params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid debug_traceCallMany params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request["id"], 100, error_msg);
        stream.write_json(reply);

        co_return;
    }
    const auto bundles = params[0].get<Bundles>();

    if (bundles.empty()) {
        const auto error_msg = "invalid debug_traceCallMany bundle list: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request["id"], 100, error_msg);
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
    stream.write_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        debug::DebugExecutor executor{tx_database, *block_cache_, workers_, *tx, config};
        co_await executor.trace_call_many(stream, bundles, simulation_context);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_traceblockbynumber
awaitable<void> DebugRpcApi::handle_debug_trace_block_by_number(const nlohmann::json& request, json::Stream& stream) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid debug_traceBlockByNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request["id"], 100, error_msg);
        stream.write_json(reply);
        co_return;
    }
    const auto block_number = params[0].get<std::uint64_t>();

    debug::DebugConfig config;
    if (params.size() > 1) {
        config = params[1].get<debug::DebugConfig>();
    }

    SILK_DEBUG << "block_number: " << block_number << " config: {" << config << "}";

    stream.open_object();
    stream.write_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        debug::DebugExecutor executor{tx_database, *block_cache_, workers_, *tx, config};
        co_await executor.trace_block(stream, block_number);
    } catch (const std::invalid_argument& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        std::ostringstream oss;
        oss << "block_number " << block_number << " not found";
        const Error error{-32000, oss.str()};
        stream.write_field("error", error);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        const Error error{100, e.what()};
        stream.write_field("error", error);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_traceblockbyhash
awaitable<void> DebugRpcApi::handle_debug_trace_block_by_hash(const nlohmann::json& request, json::Stream& stream) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid debug_traceBlockByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        const auto reply = make_json_error(request["id"], 100, error_msg);
        stream.write_json(reply);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();

    debug::DebugConfig config;
    if (params.size() > 1) {
        config = params[1].get<debug::DebugConfig>();
    }

    SILK_DEBUG << "block_hash: " << block_hash << " config: {" << config << "}";

    stream.open_object();
    stream.write_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        debug::DebugExecutor executor{tx_database, *block_cache_, workers_, *tx, config};
        co_await executor.trace_block(stream, block_hash);
    } catch (const std::invalid_argument& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        std::ostringstream oss;
        oss << "block_hash " << block_hash << " not found";
        const Error error{-32000, oss.str()};
        stream.write_field("error", error);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        const Error error{100, e.what()};
        stream.write_field("error", error);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        const Error error{100, "unexpected exception"};
        stream.write_field("error", error);
    }

    stream.close_object();

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

awaitable<std::set<evmc::address>> get_modified_accounts(ethdb::TransactionDatabase& tx_database, uint64_t start_block_number, uint64_t end_block_number) {
    const auto latest_block_number = co_await core::get_block_number(core::kLatestBlockId, tx_database);

    SILK_DEBUG << "latest: " << latest_block_number << " start: " << start_block_number << " end: " << end_block_number;

    std::set<evmc::address> addresses;
    if (start_block_number > latest_block_number) {
        std::stringstream msg;
        msg << "start block (" << start_block_number << ") is later than the latest block (" << latest_block_number << ")";
        throw std::invalid_argument(msg.str());
    } else if (start_block_number <= end_block_number) {
        core::rawdb::Walker walker = [&](const silkworm::Bytes& key, const silkworm::Bytes& value) {
            auto block_number = static_cast<uint64_t>(std::stol(silkworm::to_hex(key), nullptr, 16));
            if (block_number <= end_block_number) {
                auto address = silkworm::to_evmc_address(value.substr(0, silkworm::kAddressLength));

                SILK_TRACE << "Walker: processing block " << block_number << " address 0x" << silkworm::to_hex(address);
                addresses.insert(address);
            }
            return block_number <= end_block_number;
        };

        const auto key = silkworm::db::block_key(start_block_number);
        SILK_TRACE << "Ready to walk starting from key: " << silkworm::to_hex(key);

        co_await tx_database.walk(db::table::kAccountChangeSetName, key, 0, walker);
    }

    co_return addresses;
}

}  // namespace silkworm::rpc::commands
