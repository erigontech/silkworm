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

#include <string>

#include <silkworm/silkrpc/json/types.hpp>

#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/core/state_reader.hpp>
#include <silkworm/silkrpc/ethdb/kv/cached_database.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>

namespace silkrpc::commands {

constexpr int kCurrentApiLevel{8};

boost::asio::awaitable<void> OtsRpcApi::handle_ots_get_api_level(const nlohmann::json& request, nlohmann::json& reply) {
    reply = make_json_content(request["id"], kCurrentApiLevel);
    co_return;
}

boost::asio::awaitable<void> OtsRpcApi::handle_ots_has_code(const nlohmann::json& request, nlohmann::json& reply) {
    const auto params = request["params"];
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
        StateReader state_reader(is_latest_block ? (core::rawdb::DatabaseReader&)cached_database : (core::rawdb::DatabaseReader&)tx_database);

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

    co_await tx->close(); // RAII not (yet) available with coroutines
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
        const auto block_header = co_await core::rawdb::read_header(tx_database, block_hash, block_number);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_hash, block_number);

        const auto block_body_rlp = co_await core::rawdb::read_body_rlp(tx_database, block_hash, block_number);

        if (block_body_rlp.empty()) {
            throw std::runtime_error{"empty block body RLP in read_body"};
        }

        silkworm::ByteView data_view{block_body_rlp};
        auto stored_body{silkworm::db::detail::decode_stored_block_body(data_view)};

        const BlockDetails block_details{block_hash, block_header, total_difficulty, stored_body.txn_count -2, stored_body.ommers};

        const BlockDetailsResponse block_details_response{block_details};

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

    co_await tx->close();
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
        const auto block_header = co_await core::rawdb::read_header(tx_database, block_hash, block_number);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_hash, block_number);

        const auto block_body_rlp = co_await core::rawdb::read_body_rlp(tx_database, block_hash, block_number);

        if (block_body_rlp.empty()) {
            throw std::runtime_error{"empty block body RLP in read_body"};
        }

        silkworm::ByteView data_view{block_body_rlp};
        auto stored_body{silkworm::db::detail::decode_stored_block_body(data_view)};

        const BlockDetails block_details{block_hash, block_header, total_difficulty, stored_body.txn_count -2, stored_body.ommers};

        const BlockDetailsResponse block_details_response{block_details};

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

    co_await tx->close(); // RAII not (yet) available with coroutines
    co_return;
}

} // namespace silkrpc::commands
