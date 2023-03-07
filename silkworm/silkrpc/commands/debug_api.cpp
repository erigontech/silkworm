/*
    Copyright 2020 The Silkrpc Authors

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

#include <set>
#include <stdexcept>
#include <string>
#include <ostream>
#include <sstream>
#include <vector>
#include <utility>

#include <chrono>
#include <ctime>

#include <evmc/evmc.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/consensus/ethash/engine.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/node/db/util.hpp>

#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/account_dumper.hpp>
#include <silkworm/silkrpc/core/account_walker.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/core/evm_debug.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/core/state_reader.hpp>
#include <silkworm/silkrpc/core/storage_walker.hpp>
#include <silkworm/silkrpc/ethdb/kv/cached_database.hpp>
#include <silkworm/silkrpc/ethdb/tables.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/dump_account.hpp>

namespace silkrpc::commands {

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_accountrange
boost::asio::awaitable<void> DebugRpcApi::handle_debug_account_range(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 5) {
        auto error_msg = "invalid debug_accountRange params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
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

    SILKRPC_INFO << "block_number_or_hash: " << block_number_or_hash
        << " start_address: 0x" << silkworm::to_hex(start_address)
        << " max_result: " << max_result
        << " exclude_code: " << exclude_code
        << " exclude_storage: " << exclude_storage
        << "\n";

    auto tx = co_await database_->begin();

    try {
        auto start = std::chrono::system_clock::now();
        AccountDumper dumper{*tx};
        DumpAccounts dump_accounts = co_await dumper.dump_accounts(*context_.block_cache(), block_number_or_hash, start_address, max_result, exclude_code, exclude_storage);
        auto end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        SILKRPC_DEBUG << "dump_accounts: elapsed " << elapsed_seconds.count() << " sec\n";

        reply = make_json_content(request["id"], dump_accounts);
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close(); // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_getmodifiedaccountsbynumber
boost::asio::awaitable<void> DebugRpcApi::handle_debug_get_modified_accounts_by_number(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() == 0 || params.size() > 2) {
        auto error_msg = "invalid debug_getModifiedAccountsByNumber params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    auto start_block_id = params[0].get<std::string>();
    auto end_block_id = start_block_id;
    if (params.size() == 2) {
       end_block_id = params[1].get<std::string>();
    }
    SILKRPC_DEBUG << "start_block_id: " << start_block_id << " end_block_id: " << end_block_id << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto start_block_number = co_await core::get_block_number(start_block_id, tx_database);
        const auto end_block_number = co_await core::get_block_number(end_block_id, tx_database);

        const auto addresses = co_await get_modified_accounts(tx_database, start_block_number, end_block_number);
        reply = make_json_content(request["id"], addresses);
    } catch (const std::invalid_argument& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close(); // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_getmodifiedaccountsbyhash
boost::asio::awaitable<void> DebugRpcApi::handle_debug_get_modified_accounts_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() == 0 || params.size() > 2) {
        auto error_msg = "invalid debug_getModifiedAccountsByHash params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    auto start_hash = params[0].get<evmc::bytes32>();
    auto end_hash = start_hash;
    if (params.size() == 2) {
       end_hash = params[1].get<evmc::bytes32>();
    }
    SILKRPC_DEBUG << "start_hash: " << start_hash << " end_hash: " << end_hash << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto start_block_number = co_await core::rawdb::read_header_number(tx_database, start_hash);
        const auto end_block_number = co_await core::rawdb::read_header_number(tx_database, end_hash);
        auto addresses = co_await get_modified_accounts(tx_database, start_block_number, end_block_number);
        reply = make_json_content(request["id"], addresses);
    } catch (const std::invalid_argument& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close(); // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_storagerangeat
boost::asio::awaitable<void> DebugRpcApi::handle_debug_storage_range_at(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() == 0 || params.size() > 5) {
        auto error_msg = "invalid debug_storageRangeAt params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    auto block_hash = params[0].get<evmc::bytes32>();
    auto tx_index = params[1].get<std::uint64_t>();
    auto address = params[2].get<evmc::address>();
    auto start_key = params[3].get<evmc::bytes32>();
    auto max_result = params[4].get<std::uint64_t>();

    SILKRPC_DEBUG << "block_hash: 0x" << silkworm::to_hex(block_hash)
        << " tx_index: " << tx_index
        << " address: 0x" << silkworm::to_hex(address)
        << " start_key: 0x" << silkworm::to_hex(start_key)
        << " max_result: " << max_result
        << "\n";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::rawdb::read_block_by_hash(tx_database, block_hash);
        auto block_number = block_with_hash.block.header.number - 1;

        nlohmann::json storage({});
        silkworm::Bytes next_key;
        std::uint16_t count{0};

        silkrpc::StorageWalker::StorageCollector collector = [&](const silkworm::ByteView key, silkworm::ByteView sec_key, silkworm::ByteView value) {
            SILKRPC_TRACE << "StorageCollector: suitable for result"
                <<  " key: 0x" << silkworm::to_hex(key)
                <<  " sec_key: 0x" << silkworm::to_hex(sec_key)
                <<  " value: " << silkworm::to_hex(value)
                << "\n";

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
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close(); // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_tracetransaction
boost::asio::awaitable<void> DebugRpcApi::handle_debug_trace_transaction(const nlohmann::json& request, json::Stream& stream) {
    auto params = request["params"];
    if (params.size() < 1) {
        auto error_msg = "invalid debug_traceTransaction params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        const auto reply = make_json_error(request["id"], 100, error_msg);
        stream.write_json(reply);

        co_return;
    }
    auto transaction_hash = params[0].get<evmc::bytes32>();

    debug::DebugConfig config;
    if (params.size() > 1) {
        config = params[1].get<debug::DebugConfig>();
    }

    SILKRPC_DEBUG << "transaction_hash: " << transaction_hash << " config: {" << config << "}\n";

    stream.open_object();
    stream.write_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto tx_with_block = co_await core::read_transaction_by_hash(*context_.block_cache(), tx_database, transaction_hash);
        if (!tx_with_block) {
            std::ostringstream oss;
            oss << "transaction 0x" << transaction_hash << " not found";
            const Error error{-32000, oss.str()};
            stream.write_field("error", error);
        } else {
            debug::DebugExecutor executor{*context_.io_context(), tx_database, workers_, config};

            stream.write_field("result");
            stream.open_object();
            const auto result = co_await executor.execute(tx_with_block->block_with_hash.block, tx_with_block->transaction, &stream);
            stream.close_object();

            if (result.pre_check_error) {
                const Error error{-32000, result.pre_check_error.value()};
                stream.write_field("error", error);
            }
        }
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        const Error error{100, e.what()};
        stream.write_field("error", error);
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        const Error error{100, "unexpected exception"};
        stream.write_field("error", error);
    }

    stream.close_object();

    co_await tx->close(); // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_tracecall
boost::asio::awaitable<void> DebugRpcApi::handle_debug_trace_call(const nlohmann::json& request, json::Stream& stream) {
    auto params = request["params"];
    if (params.size() < 2) {
        auto error_msg = "invalid debug_traceCall params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
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

    SILKRPC_DEBUG << "call: " << call << " block_number_or_hash: " << block_number_or_hash << " config: {" << config << "}\n";

    stream.open_object();
    stream.write_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        ethdb::kv::CachedDatabase cached_database{block_number_or_hash, *tx, *context_.state_cache()};

        const auto block_with_hash = co_await core::read_block_by_number_or_hash(*context_.block_cache(), tx_database, block_number_or_hash);
        const bool is_latest_block = co_await core::is_latest_block_number(block_with_hash.block.header.number, tx_database);
        core::rawdb::DatabaseReader& db_reader = is_latest_block ? (core::rawdb::DatabaseReader&)cached_database : (core::rawdb::DatabaseReader&)tx_database;
        debug::DebugExecutor executor{*context_.io_context(), db_reader, workers_, config};

        stream.write_field("result");
        stream.open_object();
        const auto result = co_await executor.execute(block_with_hash.block, call, &stream);
        stream.close_object();

        if (result.pre_check_error) {
            const Error error{-32000, result.pre_check_error.value()};
            stream.write_field("error", error);
        }
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";

        std::ostringstream oss;
        oss << "block " << block_number_or_hash.number() << "(" << block_number_or_hash.hash() << ") not found";

        const Error error{-32000, oss.str()};
        stream.write_field("error", error);
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";

        const Error error{100, "unexpected exception"};
        stream.write_field("error", error);
    }

    stream.close_object();

    co_await tx->close(); // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_traceblockbynumber
boost::asio::awaitable<void> DebugRpcApi::handle_debug_trace_block_by_number(const nlohmann::json& request, json::Stream& stream) {
    auto params = request["params"];
    if (params.size() < 1) {
        auto error_msg = "invalid debug_traceBlockByNumber params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        const auto reply = make_json_error(request["id"], 100, error_msg);
        stream.write_json(reply);
        co_return;
    }
    const auto block_number = params[0].get<std::uint64_t>();

    debug::DebugConfig config;
    if (params.size() > 1) {
        config = params[1].get<debug::DebugConfig>();
    }

    SILKRPC_DEBUG << "block_number: " << block_number << " config: {" << config << "}\n";

    stream.open_object();
    stream.write_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_number(*context_.block_cache(), tx_database, block_number);

        debug::DebugExecutor executor{*context_.io_context(), tx_database, workers_, config};

        stream.write_field("result");
        stream.open_array();
        const auto debug_traces = co_await executor.execute(block_with_hash.block, &stream);
        stream.close_array();
    } catch (const std::invalid_argument& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";

        std::ostringstream oss;
        oss << "block_number " << block_number << " not found";

        const Error error{-32000, oss.str()};
        stream.write_field("error", error);
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";

        const Error error{100, e.what()};
        stream.write_field("error", error);
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";

        const Error error{100, "unexpected exception"};
        stream.write_field("error", error);
    }

    stream.close_object();

    co_await tx->close(); // RAII not (yet) available with coroutines
    co_return;
}

// https://github.com/ethereum/retesteth/wiki/RPC-Methods#debug_traceblockbyhash
boost::asio::awaitable<void> DebugRpcApi::handle_debug_trace_block_by_hash(const nlohmann::json& request, json::Stream& stream) {
    auto params = request["params"];
    if (params.size() < 1) {
        auto error_msg = "invalid debug_traceBlockByHash params: " + params.dump();
        SILKRPC_ERROR << error_msg << "\n";
        const auto reply = make_json_error(request["id"], 100, error_msg);
        stream.write_json(reply);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();

    debug::DebugConfig config;
    if (params.size() > 1) {
        config = params[1].get<debug::DebugConfig>();
    }

    SILKRPC_DEBUG << "block_hash: " << block_hash << " config: {" << config << "}\n";

    stream.open_object();
    stream.write_field("id", request["id"]);
    stream.write_field("jsonrpc", "2.0");

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_with_hash = co_await core::read_block_by_hash(*context_.block_cache(), tx_database, block_hash);

        debug::DebugExecutor executor{*context_.io_context(), tx_database, workers_, config};

        stream.write_field("result");
        stream.open_array();
        const auto debug_traces = co_await executor.execute(block_with_hash.block, &stream);
        stream.close_array();
    } catch (const std::invalid_argument& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";

        std::ostringstream oss;
        oss << "block_hash " << block_hash << " not found";

        const Error error{-32000, oss.str()};
        stream.write_field("error", error);
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";

        const Error error{100, e.what()};
        stream.write_field("error", error);
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";

        const Error error{100, "unexpected exception"};
        stream.write_field("error", error);
    }

    stream.close_object();

    co_await tx->close(); // RAII not (yet) available with coroutines
    co_return;
}

boost::asio::awaitable<std::set<evmc::address>> get_modified_accounts(ethdb::TransactionDatabase& tx_database, uint64_t start_block_number, uint64_t end_block_number) {
    const auto latest_block_number = co_await core::get_block_number(core::kLatestBlockId, tx_database);

    SILKRPC_DEBUG << "latest: " << latest_block_number << " start: " << start_block_number << " end: " << end_block_number << "\n";

    std::set<evmc::address> addresses;
    if (start_block_number > latest_block_number) {
        std::stringstream msg;
        msg << "start block (" << start_block_number << ") is later than the latest block (" << latest_block_number << ")";
        throw std::invalid_argument(msg.str());
    } else if (start_block_number <= end_block_number) {
        core::rawdb::Walker walker = [&](const silkworm::Bytes& key, const silkworm::Bytes& value) {
            auto block_number = std::stol(silkworm::to_hex(key), 0, 16);
            if (block_number <= end_block_number) {
                auto address = silkworm::to_evmc_address(value.substr(0, silkworm::kAddressLength));

                SILKRPC_TRACE << "Walker: processing block " << block_number << " address 0x" << silkworm::to_hex(address) << "\n";
                addresses.insert(address);
            }
            return block_number <= end_block_number;
        };

        const auto key = silkworm::db::block_key(start_block_number);
        SILKRPC_TRACE << "Ready to walk starting from key: " << silkworm::to_hex(key) << "\n";

        co_await tx_database.walk(db::table::kPlainAccountChangeSet, key, 0, walker);
    }

    co_return addresses;
}

} // namespace silkrpc::commands
