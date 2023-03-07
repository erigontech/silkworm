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

#include "ots_api.hpp"

#include <string>

#include <silkworm/silkrpc/json/types.hpp>

#include <silkworm/silkrpc/core/blocks.hpp>
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

} // namespace silkrpc::commands
