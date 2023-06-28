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

#include <silkworm/core/protocol/ethash_rule_set.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/evm_trace.hpp>
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
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto address = params[0].get<evmc::address>();
    const auto block_id = params[1].get<std::string>();

    SILK_DEBUG << "address: " << silkworm::to_hex(address) << " block_id: " << block_id;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        ethdb::kv::CachedDatabase cached_database{BlockNumberOrHash{block_id}, *tx, *state_cache_};
        // Check if target block is the latest one: use local state cache (if any) for target transaction
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
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

boost::asio::awaitable<void> OtsRpcApi::handle_ots_get_block_details(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid handle_ots_getBlockDetails params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();

    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        const auto block_hash = co_await core::rawdb::read_canonical_block_hash(tx_database, block_number);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_hash, block_number);
        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);

        const Block extended_block{*block_with_hash, total_difficulty, false};
        auto block_size = extended_block.get_block_size();

        const BlockDetails block_details{block_size, block_hash, block_with_hash->block.header, total_difficulty, block_with_hash->block.transactions.size(), block_with_hash->block.ommers};

        auto receipts = co_await core::get_receipts(tx_database, *block_with_hash);
        auto chain_config = co_await core::rawdb::read_chain_config(tx_database);

        IssuanceDetails issuance = get_issuance(chain_config, *block_with_hash);
        intx::uint256 total_fees = get_block_fees(chain_config, *block_with_hash, receipts, block_number);

        const BlockDetailsResponse block_details_response{block_details, issuance, total_fees};

        reply = make_json_content(request["id"], block_details_response);
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
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

boost::asio::awaitable<void> OtsRpcApi::handle_ots_get_block_details_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid ots_getBlockDetailsByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }
    auto block_hash = params[0].get<evmc::bytes32>();

    SILK_DEBUG << "block_hash: " << block_hash;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await read_header_number(tx_database, block_hash);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_hash, block_number);
        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, tx_database, block_hash);

        const Block extended_block{*block_with_hash, total_difficulty, false};
        auto block_size = extended_block.get_block_size();

        const BlockDetails block_details{block_size, block_hash, block_with_hash->block.header, total_difficulty, block_with_hash->block.transactions.size(), block_with_hash->block.ommers};

        auto receipts = co_await core::get_receipts(tx_database, *block_with_hash);
        auto chain_config = co_await core::rawdb::read_chain_config(tx_database);

        IssuanceDetails issuance = get_issuance(chain_config, *block_with_hash);
        intx::uint256 total_fees = get_block_fees(chain_config, *block_with_hash, receipts, block_number);

        const BlockDetailsResponse block_details_response{block_details, issuance, total_fees};

        reply = make_json_content(request["id"], block_details_response);
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request["id"], {});
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

boost::asio::awaitable<void> OtsRpcApi::handle_ots_get_block_transactions(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        auto error_msg = "invalid ots_getBlockTransactions params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    const auto block_id = params[0].get<std::string>();
    const auto page_number = params[1].get<std::size_t>();
    const auto page_size = params[2].get<std::size_t>();

    SILK_DEBUG << "block_id: " << block_id << " page_number: " << page_number << " page_size: " << page_size;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_number);
        const auto total_difficulty = co_await core::rawdb::read_total_difficulty(tx_database, block_with_hash->hash, block_number);
        auto receipts = co_await core::get_receipts(tx_database, *block_with_hash);

        const Block extended_block{*block_with_hash, total_difficulty, false};
        auto block_size = extended_block.get_block_size();

        auto transaction_count = block_with_hash->block.transactions.size();

        BlockTransactionsResponse block_transactions{block_size, block_with_hash->hash, block_with_hash->block.header, total_difficulty, transaction_count, block_with_hash->block.ommers};

        auto page_end = block_with_hash->block.transactions.size() - (page_size * page_number);

        if (page_end > block_with_hash->block.transactions.size()) {
            page_end = 0;
        }

        auto page_start = page_end - page_size;

        if (page_start > page_end) {
            page_start = 0;
        }

        for (auto i = page_start; i < page_end; i++) {
            block_transactions.receipts.push_back(receipts.at(i));
            block_transactions.transactions.push_back(block_with_hash->block.transactions.at(i));
        }

        reply = make_json_content(request["id"], block_transactions);

    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request["id"], {});
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

boost::asio::awaitable<void> OtsRpcApi::handle_ots_get_transaction_by_sender_and_nonce(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        const auto error_msg = "invalid ots_getTransactionBySenderAndNonce params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    const auto sender = params[0].get<evmc::address>();
    const auto nonce = params[1].get<uint64_t>();

    SILK_DEBUG << "sender: " << sender << " nonce: " << nonce;
    auto tx = co_await database_->begin();

    try {
        auto account_history_cursor = co_await tx->cursor(db::table::kAccountHistoryName);
        auto account_change_set_cursor = co_await tx->cursor_dup_sort(db::table::kAccountChangeSetName);
        auto sender_byte_view = full_view(sender);
        auto key_value = co_await account_history_cursor->seek(sender_byte_view);

        std::vector<uint64_t> account_block_numbers;

        uint64_t max_block_prev_chunk = 0;
        roaring::Roaring64Map bitmap;

        while (true) {
            if (key_value.key.empty() || !key_value.key.starts_with(sender_byte_view)) {
                auto plain_state_cursor = co_await tx->cursor(db::table::kPlainStateName);
                auto account_payload = co_await plain_state_cursor->seek(sender_byte_view);
                auto account = Account::from_encoded_storage(account_payload.value);

                if (account.has_value() && account.value().nonce > nonce) {
                    break;
                }

                reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
                co_await tx->close();
                co_return;
            }

            bitmap = db::bitmap::parse(key_value.value);
            auto const max_block = bitmap.maximum();
            auto block_key{db::block_key(max_block)};
            auto account_payload = co_await account_change_set_cursor->seek_both(block_key, sender_byte_view);
            if (account_payload.starts_with(sender_byte_view)) {
                account_payload = account_payload.substr(sender_byte_view.length());
                auto account = Account::from_encoded_storage(account_payload);

                if (account.has_value() && account.value().nonce > nonce) {
                    break;
                }
            }
            max_block_prev_chunk = max_block;
            key_value = co_await account_history_cursor->next();
        }

        uint64_t cardinality = bitmap.cardinality();
        account_block_numbers.reserve(cardinality);
        bitmap.toUint64Array(account_block_numbers.data());

        uint64_t idx = 0;
        for (uint64_t i = 0; i < cardinality; i++) {
            auto block_number = account_block_numbers[i];
            auto block_key{db::block_key(block_number)};
            auto account_payload = co_await account_change_set_cursor->seek_both(block_key, sender_byte_view);
            if (account_payload.starts_with(sender_byte_view)) {
                account_payload = account_payload.substr(sender_byte_view.length());
                auto account = Account::from_encoded_storage(account_payload);

                if (account.has_value() && account.value().nonce > nonce) {
                    idx = i;
                    break;
                }
            }
        }

        auto nonce_block = max_block_prev_chunk;
        if (idx > 0) {
            nonce_block = account_block_numbers[idx - 1];
        }

        ethdb::TransactionDatabase tx_database{*tx};
        auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, nonce_block);

        for (const auto& transaction : block_with_hash->block.transactions) {
            if (transaction.from == sender && transaction.nonce == nonce) {
                auto const transaction_hash{hash_of_transaction(transaction)};
                auto result = to_bytes32({transaction_hash.bytes, kHashLength});
                reply = make_json_content(request["id"], result);
                co_await tx->close();
                co_return;
            }
        }
        reply = make_json_content(request["id"], nlohmann::detail::value_t::null);

    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
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

boost::asio::awaitable<void> OtsRpcApi::handle_ots_get_contract_creator(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        const auto error_msg = "invalid ots_getContractCreator params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    const auto contract_address = params[0].get<evmc::address>();

    SILK_DEBUG << "contract_address: " << contract_address;

    auto tx = co_await database_->begin();

    try {
        auto contract_address_byte_view = full_view(contract_address);
        auto plain_state_cursor = co_await tx->cursor(db::table::kPlainStateName);
        auto account_payload = co_await plain_state_cursor->seek(contract_address_byte_view);
        auto plain_state_account = Account::from_encoded_storage(account_payload.value);

        if (!plain_state_account.has_value()) {
            reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
            co_await tx->close();
            co_return;
        }

        if (!plain_state_account.value().code_hash) {
            reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
            co_await tx->close();
            co_return;
        }

        auto account_history_cursor = co_await tx->cursor(db::table::kAccountHistoryName);
        auto account_change_set_cursor = co_await tx->cursor_dup_sort(db::table::kAccountChangeSetName);

        auto key_value = co_await account_history_cursor->seek(db::account_history_key(contract_address, 0));

        std::vector<uint64_t> account_block_numbers;

        uint64_t max_block_prev_chunk = 0;
        roaring::Roaring64Map bitmap;

        while (true) {
            if (key_value.key.empty() || !key_value.key.starts_with(contract_address_byte_view)) {
                reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
                co_await tx->close();
                co_return;
            }

            bitmap = db::bitmap::parse(key_value.value);
            auto const max_block = bitmap.maximum();
            auto block_key{db::block_key(max_block)};
            auto address_and_payload = co_await account_change_set_cursor->seek_both(block_key, contract_address_byte_view);
            if (!address_and_payload.starts_with(contract_address_byte_view)) {
                reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
                co_await tx->close();
                co_return;
            }
            auto payload = address_and_payload.substr(contract_address_byte_view.length());
            auto account = Account::from_encoded_storage(payload);

            if (!account) {
                reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
                co_await tx->close();
                co_return;
            }

            if (account->incarnation >= plain_state_account->incarnation) {
                break;
            }
            max_block_prev_chunk = max_block;
            key_value = co_await account_history_cursor->next();
        }

        uint64_t cardinality = bitmap.cardinality();
        account_block_numbers.resize(cardinality);
        bitmap.toUint64Array(account_block_numbers.data());

        uint64_t idx = 0;
        for (uint64_t i = 0; i < cardinality; i++) {
            auto block_number = account_block_numbers[i];
            auto block_key{db::block_key(block_number)};
            auto address_and_payload = co_await account_change_set_cursor->seek_both(block_key, contract_address_byte_view);

            if (!address_and_payload.starts_with(contract_address_byte_view)) {
                reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
                co_await tx->close();
                co_return;
            }

            auto payload = address_and_payload.substr(contract_address_byte_view.length());
            auto account = Account::from_encoded_storage(payload);

            if (!account) {
                reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
                co_await tx->close();
                co_return;
            }

            if (account.has_value() && account->incarnation >= plain_state_account->incarnation) {
                idx = i;
                break;
            }
        }

        auto block_found = max_block_prev_chunk;
        if (idx > 0) {
            block_found = account_block_numbers[idx - 1];
        }

        ethdb::TransactionDatabase tx_database{*tx};
        auto block_with_hash = co_await core::read_block_by_number(*block_cache_, tx_database, block_found);

        trace::TraceCallExecutor executor{*block_cache_, tx_database, workers_, *tx};
        const auto result = co_await executor.trace_deploy_transaction(block_with_hash->block, contract_address);

        reply = make_json_content(request["id"], result);

    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
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

boost::asio::awaitable<void> OtsRpcApi::handle_ots_trace_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        const auto error_msg = "invalid ots_traceTransaction params: " + params.dump();
        SILK_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    const auto transaction_hash = params[0].get<evmc::bytes32>();

    SILK_DEBUG << "transaction_hash: " << transaction_hash;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        trace::TraceCallExecutor executor{*block_cache_, tx_database, workers_, *tx};

        const auto transaction_with_block = co_await core::read_transaction_by_hash(*block_cache_, tx_database, transaction_hash);

        if (!transaction_with_block.has_value()) {
            reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
            co_await tx->close();
            co_return;
        }

        const auto result = co_await executor.trace_transaction_entries(transaction_with_block.value());

        reply = make_json_content(request["id"], result);

    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
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

boost::asio::awaitable<void> OtsRpcApi::handle_ots_get_transaction_error(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        const auto error_msg = "invalid ots_getTransactionError params: " + params.dump();
        SILK_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    const auto transaction_hash = params[0].get<evmc::bytes32>();

    SILK_DEBUG << "transaction_hash: " << transaction_hash;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        trace::TraceCallExecutor executor{*block_cache_, tx_database, workers_, *tx};

        const auto transaction_with_block = co_await core::read_transaction_by_hash(*block_cache_, tx_database, transaction_hash);

        if (!transaction_with_block.has_value()) {
            reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
            co_await tx->close();
            co_return;
        }

        const auto result = co_await executor.trace_transaction_error(transaction_with_block.value());

        reply = make_json_content(request["id"], result);

    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
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

boost::asio::awaitable<void> OtsRpcApi::handle_ots_get_internal_operations(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        const auto error_msg = "invalid ots_getInternalOperations params: " + params.dump();
        SILK_ERROR << error_msg << "\n";
        reply = make_json_error(request["id"], 100, error_msg);
        co_return;
    }

    const auto transaction_hash = params[0].get<evmc::bytes32>();

    SILK_DEBUG << "transaction_hash: " << transaction_hash;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        trace::TraceCallExecutor executor{*block_cache_, tx_database, workers_, *tx};

        const auto transaction_with_block = co_await core::read_transaction_by_hash(*block_cache_, tx_database, transaction_hash);

        if (!transaction_with_block.has_value()) {
            reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
            co_await tx->close();
            co_return;
        }

        const auto result = co_await executor.trace_operations(transaction_with_block.value());

        reply = make_json_content(request["id"], result);

    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request["id"], nlohmann::detail::value_t::null);
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

IssuanceDetails OtsRpcApi::get_issuance(const ChainConfig& chain_config, const silkworm::BlockWithHash& block) {
    auto config = silkworm::ChainConfig::from_json(chain_config.config).value();

    if (config.protocol_rule_set != protocol::RuleSetType::kEthash) {
        return IssuanceDetails{};
    }

    auto block_reward = protocol::EthashRuleSet::compute_reward(config, block.block);

    intx::uint256 ommers_reward = std::accumulate(block_reward.ommers.begin(), block_reward.ommers.end(), intx::uint256{0});

    IssuanceDetails issuance{
        .miner_reward = block_reward.miner,
        .ommers_reward = ommers_reward,
        .total_reward = block_reward.miner + ommers_reward};

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
