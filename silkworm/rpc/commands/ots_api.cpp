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
#include <utility>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/protocol/ethash_rule_set.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/kv/api/endpoint/key_value.hpp>
#include <silkworm/db/kv/state_reader.hpp>
#include <silkworm/db/kv/txn_num.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/execution/state_factory.hpp>
#include <silkworm/infra/common/async_binary_search.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/evm_trace.hpp>
#include <silkworm/rpc/core/receipts.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::rpc::commands {

using namespace silkworm::db;
using db::kv::StateReader;
namespace bitmap {
    using namespace silkworm::datastore::kvdb::bitmap;
}

static constexpr int kCurrentApiLevel{8};

//! The window size used when probing history periodically
static constexpr uint64_t kTxnProbeWindowSize{4096};

Task<void> OtsRpcApi::handle_ots_get_api_level(const nlohmann::json& request, nlohmann::json& reply) {
    reply = make_json_content(request, kCurrentApiLevel);
    co_return;
}

Task<void> OtsRpcApi::handle_ots_has_code(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        const auto error_msg = "invalid ots_hasCode params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto address = params[0].get<evmc::address>();
    const auto block_id = params[1].is_string() ? params[1].get<std::string>() : to_quantity(params[1].get<uint64_t>());

    SILK_DEBUG << "address: " << address << " block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};

        // Check if target block is the latest one: use local state cache (if any) for target transaction
        const bool is_latest_block = co_await block_reader.is_latest_block_num(BlockNumOrHash{block_id});
        tx->set_state_cache_enabled(is_latest_block);

        const auto block_num = co_await block_reader.get_block_num(block_id);
        execution::StateFactory state_factory{*tx};
        const auto txn_id = co_await state_factory.user_txn_id_at(block_num + 1);

        StateReader state_reader{*tx, txn_id};
        std::optional<silkworm::Account> account{co_await state_reader.read_account(address)};

        if (account) {
            auto code{co_await state_reader.read_code(address, account->code_hash)};
            reply = make_json_content(request, code.has_value());
        } else {
            reply = make_json_content(request, false);
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_content(request, false);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<void> OtsRpcApi::handle_ots_get_block_details(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid handle_ots_getBlockDetails params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto block_id = params[0].is_string() ? params[0].get<std::string>() : to_quantity(params[0].get<uint64_t>());

    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num = co_await block_reader.get_block_num(block_id);
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (block_with_hash) {
            const Block extended_block{block_with_hash, false};
            const auto block_size = extended_block.get_block_size();
            const BlockDetails block_details{block_size, block_with_hash->hash, block_with_hash->block.header,
                                             block_with_hash->block.transactions.size(), block_with_hash->block.ommers,
                                             block_with_hash->block.withdrawals};
            const auto receipts = co_await core::get_receipts(*tx, *block_with_hash, *chain_storage, workers_);
            const auto chain_config = co_await chain_storage->read_chain_config();
            const IssuanceDetails issuance = get_issuance(chain_config, *block_with_hash);
            const intx::uint256 total_fees = get_block_fees(*block_with_hash, receipts);
            const BlockDetailsResponse block_details_response{block_details, issuance, total_fees};
            reply = make_json_content(request, block_details_response);
        } else {
            reply = make_json_content(request, nlohmann::detail::value_t::null);
        }
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, nlohmann::detail::value_t::null);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<void> OtsRpcApi::handle_ots_get_block_details_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid ots_getBlockDetailsByHash params: " + params.dump();
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
            const Block extended_block{block_with_hash, false};
            const auto block_size = extended_block.get_block_size();
            const BlockDetails block_details{block_size, block_with_hash->hash, block_with_hash->block.header,
                                             block_with_hash->block.transactions.size(), block_with_hash->block.ommers,
                                             block_with_hash->block.withdrawals};
            const auto receipts = co_await core::get_receipts(*tx, *block_with_hash, *chain_storage, workers_);
            const auto chain_config = co_await chain_storage->read_chain_config();
            const IssuanceDetails issuance = get_issuance(chain_config, *block_with_hash);
            const intx::uint256 total_fees = get_block_fees(*block_with_hash, receipts);
            const BlockDetailsResponse block_details_response{block_details, issuance, total_fees};
            reply = make_json_content(request, block_details_response);
        } else {
            reply = make_json_content(request, nlohmann::detail::value_t::null);
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

Task<void> OtsRpcApi::handle_ots_get_block_transactions(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        auto error_msg = "invalid ots_getBlockTransactions params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto block_id = params[0].is_string() ? params[0].get<std::string>() : to_quantity(params[0].get<uint64_t>());
    const auto page_number = params[1].get<size_t>();
    const auto page_size = params[2].get<size_t>();

    SILK_DEBUG << "block_id: " << block_id << " page_number: " << page_number << " page_size: " << page_size;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};

        const auto block_num = co_await block_reader.get_block_num(block_id);

        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
        if (block_with_hash) {
            const Block extended_block{block_with_hash, false};
            auto receipts = co_await core::get_receipts(*tx, *block_with_hash, *chain_storage, workers_);
            auto block_size = extended_block.get_block_size();
            auto transaction_count = block_with_hash->block.transactions.size();

            BlockTransactionsResponse block_transactions{
                block_size,
                block_with_hash->hash,
                block_with_hash->block.header,
                transaction_count,
                block_with_hash->block.ommers,
                {},  // receipt
                {},  // transactions
                block_with_hash->block.withdrawals};

            auto page_end = block_with_hash->block.transactions.size() - (page_size * page_number);

            if (page_end > block_with_hash->block.transactions.size()) {
                page_end = 0;
            }

            auto page_start = page_end - page_size;

            if (page_start > page_end) {
                page_start = 0;
            }

            for (auto i = page_start; i < page_end; ++i) {
                block_transactions.receipts.push_back(receipts.at(i));
                block_transactions.transactions.push_back(block_with_hash->block.transactions.at(i));
            }

            reply = make_json_content(request, block_transactions);
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

Task<void> OtsRpcApi::handle_ots_get_transaction_by_sender_and_nonce(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 2) {
        const auto error_msg = "invalid ots_getTransactionBySenderAndNonce params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto sender = params[0].get<evmc::address>();
    const auto nonce = params[1].get<uint64_t>();

    SILK_DEBUG << "sender: " << sender << ", nonce: " << nonce;
    auto tx = co_await database_->begin_transaction();

    try {
        auto key = db::code_domain_key(sender);

        db::kv::api::IndexRangeQuery query{
            .table = db::table::kAccountsHistoryIdx,
            .key = key,
            .from_timestamp = -1,
            .to_timestamp = -1,
            .ascending_order = true};
        auto paginated_result = co_await tx->index_range(std::move(query));
        auto it = co_await paginated_result.begin();

        std::vector<std::string> keys;
        uint64_t count = 0;
        TxnId prev_txn_id = 0;
        TxnId next_txn_id = 0;
        while (const auto value = co_await it->next()) {
            const auto txn_id = static_cast<TxnId>(*value);
            if (count++ % kTxnProbeWindowSize != 0) {
                next_txn_id = txn_id;
                continue;
            }
            SILK_DEBUG << "count: " << count << ", txnId: " << txn_id;
            db::kv::api::HistoryPointQuery hpq{
                .table = db::table::kAccountDomain,
                .key = key,
                .timestamp = *value};
            auto result = co_await tx->history_seek(std::move(hpq));
            if (!result.success) {
                reply = make_json_content(request, nlohmann::detail::value_t::null);
                co_await tx->close();
                co_return;
            }
            SILK_DEBUG << "history: len:" << result.value.size() << " [" << result.value << "]";

            if (result.value.empty()) {
                SILK_DEBUG << "history bytes empty";
                prev_txn_id = txn_id;
                continue;
            }
            const auto account{db::state::AccountCodec::from_encoded_storage_v3(result.value)};
            SILK_DEBUG << "Account: " << *account;
            if (account->nonce > nonce) {
                break;
            }
            prev_txn_id = txn_id;
        }
        SILK_DEBUG << "range -> prev_txn_id: " << prev_txn_id << ", next_txn_id: " << next_txn_id;

        if (next_txn_id == 0) {
            next_txn_id = prev_txn_id + 1;
        }

        db::txn::TxNum creation_txn_id = 0;
        auto index = co_await async_binary_search(static_cast<size_t>(next_txn_id - prev_txn_id), [&](size_t i) -> Task<bool> {
            auto txn_id = i + prev_txn_id;

            SILK_DEBUG << "searching for txnId: " << txn_id << ", i: " << i;
            db::kv::api::HistoryPointQuery hpq{
                .table = db::table::kAccountDomain,
                .key = key,
                .timestamp = static_cast<db::kv::api::Timestamp>(txn_id)};
            auto result = co_await tx->history_seek(std::move(hpq));
            if (!result.success) {
                co_return false;
            }
            if (result.value.empty()) {
                creation_txn_id = static_cast<uint64_t>(txn_id);
                co_return false;
            }
            const auto account{db::state::AccountCodec::from_encoded_storage_v3(result.value)};
            SILK_DEBUG << "account.nonce: " << account->nonce << ", nonce: " << nonce;
            if (account->nonce <= nonce) {
                creation_txn_id = std::max(creation_txn_id, static_cast<uint64_t>(txn_id));
                co_return false;
            }
            co_return true;
        });
        SILK_DEBUG << "after search -> index: " << index << " creationTxnId: " << creation_txn_id;

        if (creation_txn_id == 0) {
            SILK_DEBUG << "binary search in [" << prev_txn_id << ", " << next_txn_id << "] found nothing";
            reply = make_json_content(request, nlohmann::detail::value_t::null);
        }

        auto provider = ethdb::kv::canonical_body_for_storage_provider(backend_);
        const auto block_num_opt = co_await db::txn::block_num_from_tx_num(*tx, creation_txn_id, provider);
        if (block_num_opt) {
            const auto block_num = block_num_opt.value();
            const auto min_txn_id = co_await db::txn::min_tx_num(*tx, block_num, provider);
            const auto first_txn_id = co_await tx->first_txn_num_in_block(block_num);
            SILK_DEBUG << "block_num: " << block_num << ", min_txn_id: " << min_txn_id << ", first_txn_id: " << first_txn_id;

            TxnId tx_index{0};
            if (creation_txn_id == min_txn_id) {
                tx_index = index + prev_txn_id - min_txn_id - 1;
            } else {
                tx_index = creation_txn_id - min_txn_id - 1;
            }
            SILK_DEBUG << "block_num: " << block_num << ", tx_index: " << tx_index;

            const auto chain_storage{tx->create_storage()};

            const auto transaction = co_await chain_storage->read_transaction_by_idx_in_block(block_num, tx_index);
            if (!transaction) {
                SILK_DEBUG << "No transaction found in block " << block_num << " for index " << tx_index;
                reply = make_json_content(request, nlohmann::detail::value_t::null);
            } else if (transaction.value().nonce != nonce) {
                SILK_DEBUG << "Transaction nonce " << transaction.value().nonce << " doesn't match required nonce " << nonce;
                reply = make_json_content(request, nlohmann::detail::value_t::null);
            } else {
                reply = make_json_content(request, transaction.value().hash());
            }
        } else {
            SILK_INFO << "No block found for txn_id " << creation_txn_id;
            reply = make_json_content(request, nlohmann::detail::value_t::null);
        }
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, nlohmann::detail::value_t::null);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<void> OtsRpcApi::handle_ots_get_contract_creator(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        const auto error_msg = "invalid ots_getContractCreator params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto contract_address = params[0].get<evmc::address>();

    SILK_DEBUG << "contract_address: " << contract_address;

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        rpc::BlockReader block_reader{*chain_storage, *tx};
        auto block_num = co_await block_reader.get_latest_block_num();
        execution::StateFactory state_factory{*tx};
        const auto txn_number = co_await state_factory.user_txn_id_at(block_num);

        StateReader state_reader{*tx, txn_number};
        std::optional<silkworm::Account> account_opt{co_await state_reader.read_account(contract_address)};
        if (!account_opt || account_opt.value().code_hash == kEmptyHash) {
            reply = make_json_content(request, nlohmann::detail::value_t::null);
            co_await tx->close();
            co_return;
        }

        // We're searching for the creation txn of the given contract: popular contracts may have dozens of state changes
        // due to ETH deposits/withdrawals after contract creation, so it is optimal to search from the beginning even if
        // the contract has multiple incarnations.
        // Navigate forward on history index of accounts and probe history periodically (cheaper than traversing history)
        // so as a result we'll have small range of blocks for binary search or full scan.
        const auto key = db::code_domain_key(contract_address);
        db::kv::api::IndexRangeQuery query{
            .table = db::table::kAccountsHistoryIdx,
            .key = key,
            .from_timestamp = 0,
            .to_timestamp = -1,
            .ascending_order = true};
        auto paginated_result = co_await tx->index_range(std::move(query));
        auto it = co_await paginated_result.begin();

        uint64_t count = 0;
        TxnId prev_txn_id = 0;
        TxnId next_txn_id = 0;
        while (const auto value = co_await it->next()) {
            const auto txn_id = static_cast<TxnId>(*value);
            if (count++ % kTxnProbeWindowSize != 0) {
                next_txn_id = txn_id;
                continue;
            }
            SILK_DEBUG << "txn_id:" << txn_id << ", count: " << count;

            db::kv::api::HistoryPointQuery hpq{
                .table = db::table::kAccountDomain,
                .key = key,
                .timestamp = *value};
            auto result = co_await tx->history_seek(std::move(hpq));
            if (!result.success) {
                reply = make_json_content(request, nlohmann::detail::value_t::null);
                co_await tx->close();
                co_return;
            }

            if (result.value.empty()) {
                SILK_DEBUG << "history bytes empty";
                prev_txn_id = txn_id;
                continue;
            }
            const auto account{db::state::AccountCodec::from_encoded_storage_v3(result.value)};
            SILK_DEBUG << "Decoded account: " << *account;

            if (account->incarnation == account_opt.value().incarnation) {
                next_txn_id = txn_id;
                break;
            }
            prev_txn_id = txn_id;
        }
        if (next_txn_id == 0) {
            next_txn_id = prev_txn_id + 1;
        }

        db::txn::TxNum creation_txn_id = 0;
        auto index = co_await async_binary_search(static_cast<size_t>(next_txn_id - prev_txn_id), [&](size_t i) -> Task<bool> {
            auto txn_id = i + prev_txn_id;

            db::kv::api::HistoryPointQuery hpq{
                .table = db::table::kAccountDomain,
                .key = key,
                .timestamp = static_cast<db::kv::api::Timestamp>(txn_id)};
            auto result = co_await tx->history_seek(std::move(hpq));
            if (!result.success) {
                co_return false;
            }
            if (result.value.empty()) {
                creation_txn_id = std::max(static_cast<uint64_t>(txn_id), creation_txn_id);
                co_return false;
            }
            co_return true;
        });

        if (creation_txn_id == 0) {
            SILK_DEBUG << "binary search in [" << prev_txn_id << ", " << next_txn_id << "] found nothing";
            reply = make_json_content(request, nlohmann::detail::value_t::null);
        }
        auto provider = ethdb::kv::canonical_body_for_storage_provider(backend_);
        const auto block_num_opt = co_await db::txn::block_num_from_tx_num(*tx, creation_txn_id, provider);
        if (block_num_opt) {
            block_num = block_num_opt.value();
            const auto min_txn_id = co_await db::txn::min_tx_num(*tx, block_num, provider);
            const auto first_txn_id = co_await tx->first_txn_num_in_block(block_num);
            SILK_DEBUG << "block_num: " << block_num
                       << ", min_txn_id: " << min_txn_id
                       << ", first_txn_id: " << first_txn_id;

            TxnId tx_index{0};
            if (creation_txn_id == min_txn_id) {
                tx_index = index + prev_txn_id - min_txn_id - 1;
            } else {
                tx_index = creation_txn_id - min_txn_id - 1;
            }

            const auto transaction = co_await chain_storage->read_transaction_by_idx_in_block(block_num, tx_index);
            if (!transaction) {
                SILK_DEBUG << "No transaction found in block " << block_num << " for index " << tx_index;
                reply = make_json_content(request, nlohmann::detail::value_t::null);
                co_await tx->close();
                co_return;
            }

            const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);

            if (block_with_hash) {
                trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};
                const auto result = co_await executor.trace_deploy_transaction(block_with_hash->block, contract_address);
                reply = make_json_content(request, result);
            } else {
                reply = make_json_content(request, nlohmann::detail::value_t::null);
            }
        } else {
            SILK_DEBUG << "No block found for txn_id " << creation_txn_id;
            reply = make_json_content(request, nlohmann::detail::value_t::null);
        }
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, nlohmann::detail::value_t::null);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<void> OtsRpcApi::handle_ots_trace_transaction(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        const auto error_msg = "invalid ots_traceTransaction params: " + params.dump();
        SILK_ERROR << error_msg << "\n";
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto transaction_hash = params[0].get<evmc::bytes32>();

    SILK_DEBUG << "transaction_hash: " << silkworm::to_hex(transaction_hash);

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};

        const auto transaction_with_block = co_await core::read_transaction_by_hash(*block_cache_, *chain_storage, transaction_hash);

        if (!transaction_with_block.has_value()) {
            const auto error_msg = "transaction 0x" + silkworm::to_hex(transaction_hash) + " not found";
            reply = make_json_error(request, kServerError, error_msg);
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }

        const auto result = co_await executor.trace_transaction_entries(transaction_with_block.value());

        reply = make_json_content(request, result);

    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, nlohmann::detail::value_t::null);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<void> OtsRpcApi::handle_ots_get_transaction_error(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        const auto error_msg = "invalid ots_getTransactionError params: " + params.dump();
        SILK_ERROR << error_msg << "\n";
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto transaction_hash = params[0].get<evmc::bytes32>();

    SILK_DEBUG << "transaction_hash: " << silkworm::to_hex(transaction_hash);

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};

        const auto transaction_with_block = co_await core::read_transaction_by_hash(*block_cache_, *chain_storage, transaction_hash);

        if (!transaction_with_block.has_value()) {
            const auto error_msg = "transaction 0x" + silkworm::to_hex(transaction_hash) + " not found";
            reply = make_json_error(request, kServerError, error_msg);
            co_await tx->close();
            co_return;
        }

        const auto result = co_await executor.trace_transaction_error(transaction_with_block.value());

        reply = make_json_content(request, result);

    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, nlohmann::detail::value_t::null);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<void> OtsRpcApi::handle_ots_get_internal_operations(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        const auto error_msg = "invalid ots_getInternalOperations params: " + params.dump();
        SILK_ERROR << error_msg << "\n";
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto transaction_hash = params[0].get<evmc::bytes32>();

    SILK_DEBUG << "transaction_hash: " << silkworm::to_hex(transaction_hash);

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage{tx->create_storage()};
        trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, *tx};

        const auto transaction_with_block = co_await core::read_transaction_by_hash(*block_cache_, *chain_storage, transaction_hash);

        if (!transaction_with_block.has_value()) {
            const auto error_msg = "transaction 0x" + silkworm::to_hex(transaction_hash) + " not found";
            reply = make_json_error(request, kServerError, error_msg);
            co_await tx->close();
            co_return;
        }

        const auto result = co_await executor.trace_operations(transaction_with_block.value());

        reply = make_json_content(request, result);

    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, nlohmann::detail::value_t::null);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

struct BlockInfo {
    BlockNum block_num{0};
    BlockDetails details;
};

Task<void> OtsRpcApi::handle_ots_search_transactions_before(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        const auto error_msg = "invalid ots_search_transactions_before params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto address = params[0].get<evmc::address>();
    auto block_num = params[1].get<BlockNum>();
    const auto page_size = params[2].get<uint64_t>();

    SILK_DEBUG << "address: " << address << ", block_num: " << block_num << ", page_size: " << page_size;

    if (page_size > kMaxPageSize) {
        auto error_msg = "max allowed page size: " + std::to_string(kMaxPageSize);
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    if (block_num > 0) {
        --block_num;
    }
    auto tx = co_await database_->begin_transaction();
    try {
        auto provider = ethdb::kv::canonical_body_for_storage_provider(backend_);

        db::kv::api::Timestamp from_timestamp{-1};
        if (block_num > 0) {
            const auto max_tx_num = co_await db::txn::max_tx_num(*tx, block_num, provider);
            from_timestamp = static_cast<db::kv::api::Timestamp>(max_tx_num);
            SILK_DEBUG << "block_num: " << block_num << " max_tx_num: " << max_tx_num;
        }

        const auto results = co_await collect_transactions_with_receipts(*tx, provider, block_num, address, from_timestamp, false, page_size);

        reply = make_json_content(request, results);
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, nlohmann::detail::value_t::null);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<void> OtsRpcApi::handle_ots_search_transactions_after(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 3) {
        const auto error_msg = "invalid handle_ots_search_transactions_after params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }

    const auto address = params[0].get<evmc::address>();
    auto block_num = params[1].get<BlockNum>();
    const auto page_size = params[2].get<uint64_t>();

    SILK_DEBUG << "address: " << address << " block_num: " << block_num << " page_size: " << page_size;

    if (page_size > kMaxPageSize) {
        auto error_msg = "max allowed page size: " + std::to_string(kMaxPageSize);
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    auto tx = co_await database_->begin_transaction();

    try {
        auto provider = ethdb::kv::canonical_body_for_storage_provider(backend_);

        db::kv::api::Timestamp from_timestamp{-1};
        if (block_num > 0) {
            const auto max_tx_num = co_await db::txn::min_tx_num(*tx, block_num + 1, provider);
            from_timestamp = static_cast<db::kv::api::Timestamp>(max_tx_num);
            SILK_DEBUG << "block_num: " << block_num << " max_tx_num: " << max_tx_num;
        }

        auto results = co_await collect_transactions_with_receipts(*tx, provider, block_num, address, from_timestamp, true, page_size);

        std::reverse(results.transactions.begin(), results.transactions.end());
        std::reverse(results.receipts.begin(), results.receipts.end());
        std::reverse(results.blocks.begin(), results.blocks.end());

        reply = make_json_content(request, results);
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, nlohmann::detail::value_t::null);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
}

Task<TransactionsWithReceipts> OtsRpcApi::collect_transactions_with_receipts(
    kv::api::Transaction& tx,
    db::chain::CanonicalBodyForStorageProvider& provider,
    BlockNum block_num_param,
    const evmc::address& address,
    db::kv::api::Timestamp from_timestamp,
    bool ascending, uint64_t page_size) {
    const auto key = db::code_domain_key(address);
    db::kv::api::IndexRangeQuery query_to{
        .table = db::table::kTracesToIdx,
        .key = key,
        .from_timestamp = from_timestamp,
        .to_timestamp = -1,
        .ascending_order = ascending};
    auto paginated_result_to = co_await tx.index_range(std::move(query_to));

    db::kv::api::IndexRangeQuery query_from{
        .table = db::table::kTracesFromIdx,
        .key = key,
        .from_timestamp = from_timestamp,
        .to_timestamp = -1,
        .ascending_order = ascending};
    auto paginated_result_from = co_await tx.index_range(std::move(query_from));

    auto it_from = co_await paginated_result_from.begin();
    auto it_to = co_await paginated_result_to.begin();

    TransactionsWithReceipts results;
    if (ascending) {
        results.first_page = true;
        results.last_page = block_num_param == 0;
    } else {
        results.first_page = block_num_param == 0;
        results.last_page = true;
    }

    std::map<std::string, Receipt> receipts;
    std::optional<BlockInfo> block_info;

    auto paginated_stream = db::kv::api::set_union(std::move(it_from), std::move(it_to), ascending);
    auto txn_nums_it = db::txn::make_txn_nums_stream(std::move(paginated_stream), ascending, tx, provider);
    const auto chain_storage = tx.create_storage();

    while (const auto tnx_nums = co_await txn_nums_it->next()) {
        SILK_DEBUG
            << "txn_id: " << tnx_nums->txn_id
            << " block_num: " << tnx_nums->block_num
            << ", txn_index: " << tnx_nums->txn_index
            << ", final txn: " << tnx_nums->final_txn
            << ", ascending: " << std::boolalpha << ascending;

        if (tnx_nums->final_txn) {
            continue;
        }

        if (tnx_nums->block_changed) {
            block_info.reset();
        }

        if (!block_info) {
            const auto block_with_hash = co_await rpc::core::read_block_by_number(*block_cache_, *chain_storage, tnx_nums->block_num);
            if (!block_with_hash) {
                SILK_DEBUG << "Not found block no.  " << tnx_nums->block_num;
                co_return results;
            }

            auto rr = co_await core::get_receipts(tx, *block_with_hash, *chain_storage, workers_);
            SILK_DEBUG << "Read #" << rr.size() << " receipts from block " << tnx_nums->block_num;

            std::for_each(rr.begin(), rr.end(), [&receipts](const auto& item) {
                receipts[silkworm::to_hex(item.tx_hash, false)] = std::move(item);
            });

            const Block extended_block{block_with_hash, false};
            const auto block_size = extended_block.get_block_size();
            const BlockDetails block_details{block_size, block_with_hash->hash, block_with_hash->block.header,
                                             block_with_hash->block.transactions.size(), block_with_hash->block.ommers,
                                             block_with_hash->block.withdrawals};
            block_info = BlockInfo{block_with_hash->block.header.number, block_details};
        }
        if (results.transactions.size() >= page_size && tnx_nums->block_changed) {
            if (ascending) {
                results.first_page = false;
            } else {
                results.last_page = false;
            }
            break;
        }

        const auto transaction = co_await chain_storage->read_transaction_by_idx_in_block(tnx_nums->block_num, tnx_nums->txn_index);
        if (!transaction) {
            SILK_DEBUG << "No transaction found in block " << tnx_nums->block_num << " for index " << tnx_nums->txn_index;
            co_return results;
        }
        results.receipts.push_back(std::move(receipts.at(silkworm::to_hex(transaction.value().hash(), false))));
        results.transactions.push_back(std::move(transaction.value()));
        results.blocks.push_back(block_info.value().details);
    }

    SILK_DEBUG << "Results"
               << " transactions size: " << results.transactions.size()
               << " receipts size: " << results.receipts.size()
               << " block details size: " << results.blocks.size();

    co_return results;
}

Task<bool> OtsRpcApi::trace_blocks(
    FromToBlockProvider& from_to_provider,
    kv::api::Transaction& tx,
    const evmc::address& address,
    uint64_t page_size,
    uint64_t result_count,
    std::vector<TransactionsWithReceipts>& results) {
    uint64_t est_blocks_to_trace = page_size - result_count;
    bool has_more = true;
    results.clear();
    results.reserve(est_blocks_to_trace);

    for (size_t i = 0; i < est_blocks_to_trace; ++i) {
        TransactionsWithReceipts transactions_with_receipts;

        auto from_to_response = co_await from_to_provider.get();  // extract_next_block(from_cursor,to_cursor);
        auto next_block = from_to_response.block_num;
        has_more = from_to_response.has_more;
        if (!from_to_response.has_more && next_block == 0) {
            break;
        }

        co_await trace_block(tx, next_block, address, transactions_with_receipts);
        results.push_back(std::move(transactions_with_receipts));
    }

    co_return has_more;
}

Task<void> OtsRpcApi::trace_block(kv::api::Transaction& tx, BlockNum block_num, const evmc::address& search_addr, TransactionsWithReceipts& results) {
    const auto chain_storage = tx.create_storage();
    const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_num);
    if (!block_with_hash) {
        co_return;
    }

    const auto receipts = co_await core::get_receipts(tx, *block_with_hash, *chain_storage, workers_);
    const Block extended_block{block_with_hash, false};

    trace::TraceCallExecutor executor{*block_cache_, *chain_storage, workers_, tx};
    co_await executor.trace_touch_block(*block_with_hash, search_addr, extended_block.get_block_size(), receipts, results);
}

IssuanceDetails OtsRpcApi::get_issuance(const silkworm::ChainConfig& config, const silkworm::BlockWithHash& block) {
    const auto rule_set_factory = protocol::rule_set_factory(config);
    const auto block_reward{rule_set_factory->compute_reward(block.block)};

    intx::uint256 ommers_reward = std::accumulate(block_reward.ommers.begin(), block_reward.ommers.end(), intx::uint256{0});

    IssuanceDetails issuance{
        .miner_reward = block_reward.miner,
        .ommers_reward = ommers_reward,
        .total_reward = block_reward.miner + ommers_reward};

    return issuance;
}

intx::uint256 OtsRpcApi::get_block_fees(const silkworm::BlockWithHash& block, const std::vector<Receipt>& receipts) {
    intx::uint256 fees = 0;
    for (const auto& receipt : receipts) {
        auto& txn = block.block.transactions[receipt.tx_index];

        // effective_gas_price contains already baseFee
        intx::uint256 base_fee = block.block.header.base_fee_per_gas.value_or(0);
        const auto effective_gas_price = txn.effective_gas_price(base_fee);

        fees += effective_gas_price * receipt.gas_used;
    }
    return fees;
}

Task<ChunkProviderResponse> ChunkProvider::get() {
    if (error_) {
        co_return ChunkProviderResponse{Bytes{0}, false, true};
    }

    if (eof_) {
        co_return ChunkProviderResponse{Bytes{0}, false, false};
    }

    KeyValue key_value;

    try {
        if (first_) {
            first_ = false;
            key_value = first_seek_key_value_;
        } else {
            if (navigate_forward_) {
                key_value = co_await cursor_->next();
            } else {
                key_value = co_await cursor_->previous();
            }
        }
    } catch (const std::exception& e) {
        error_ = true;
    }

    if (error_) {
        eof_ = true;
        co_return ChunkProviderResponse{Bytes{0}, false, true};
    }

    if (key_value.key.empty() || !key_value.key.starts_with(address_)) {
        eof_ = true;
        co_return ChunkProviderResponse{Bytes{0}, false, false};
    }

    co_return ChunkProviderResponse{key_value.value, true, false};
}

ChunkProvider::ChunkProvider(kv::api::Cursor* cursor, const evmc::address& address,
                             bool navigate_forward, kv::api::KeyValue first_seek_key_value)
    : cursor_{cursor},
      address_{address},
      navigate_forward_{navigate_forward},
      first_seek_key_value_{std::move(first_seek_key_value)} {
}

Task<ChunkLocatorResponse> ChunkLocator::get(BlockNum min_block) {
    KeyValue key_value;
    try {
        key_value = co_await cursor_->seek(account_history_key(address_, min_block));

        if (key_value.key.empty()) {
            co_return ChunkLocatorResponse{ChunkProvider{cursor_, address_, navigate_forward_, key_value}, false, false};
        }

        co_return ChunkLocatorResponse{ChunkProvider{cursor_, address_, navigate_forward_, key_value}, true, false};

    } catch (const std::exception& e) {
        co_return ChunkLocatorResponse{ChunkProvider{cursor_, address_, navigate_forward_, key_value}, false, true};
    }
}

ChunkLocator::ChunkLocator(kv::api::Cursor* cursor, const evmc::address& address, bool navigate_forward)
    : cursor_{cursor},
      address_{address},
      navigate_forward_{navigate_forward} {
}

Task<BlockProviderResponse> ForwardBlockProvider::get() {
    if (finished_) {
        co_return BlockProviderResponse{0, false, false};
    }

    if (is_first_) {
        is_first_ = false;

        auto chunk_loc_res = co_await chunk_locator_.get(min_block_);
        chunk_provider_ = chunk_loc_res.chunk_provider;

        if (chunk_loc_res.error) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, true};
        }

        if (!chunk_loc_res.ok) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, false};
        }

        auto chunk_provider_res = co_await chunk_provider_.get();

        if (chunk_provider_res.error) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, true};
        }

        if (!chunk_provider_res.ok) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, false};
        }

        try {
            roaring::Roaring64Map bitmap = bitmap::parse(chunk_provider_res.chunk);

            iterator(bitmap);

            // It can happen that on the first chunk we'll get a chunk that contains
            // the first block >= minBlock in the middle of the chunk/bitmap, so we
            // skip all previous blocks before it.
            advance_if_needed(min_block_);

            // This means it is the last chunk and the min block is > the last one
            if (!has_next()) {
                finished_ = true;
                co_return BlockProviderResponse{0, false, false};
            }

        } catch (std::exception& e) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, true};
        }
    }

    BlockNum next_block = next();
    bool next = has_next();

    if (!next) {
        auto chunk_provider_res = co_await chunk_provider_.get();

        if (chunk_provider_res.error) {
            co_return BlockProviderResponse{0, false, true};
        }

        if (!chunk_provider_res.ok) {
            finished_ = true;
            co_return BlockProviderResponse{next_block, false, false};
        }

        next = true;

        try {
            auto bitmap = bitmap::parse(chunk_provider_res.chunk);
            iterator(bitmap);

        } catch (std::exception& e) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, true};
        }
    }

    co_return BlockProviderResponse{next_block, next, false};
}

bool ForwardBlockProvider::has_next() {
    return bitmap_index_ < bitmap_vector_.size();
}

BlockNum ForwardBlockProvider::next() {
    uint64_t result = bitmap_vector_.at(bitmap_index_);
    ++bitmap_index_;
    return result;
}

void ForwardBlockProvider::iterator(roaring::Roaring64Map& bitmap) {
    bitmap_vector_.resize(bitmap.cardinality());
    bitmap.toUint64Array(bitmap_vector_.data());
    bitmap_index_ = 0;
}

void ForwardBlockProvider::advance_if_needed(BlockNum min_block) {
    auto found_index = bitmap_vector_.size();
    for (size_t i = bitmap_index_; i < bitmap_vector_.size(); ++i) {
        if (bitmap_vector_.at(i) >= min_block) {
            found_index = i;
            break;
        }
    }
    bitmap_index_ = found_index;
}

Task<BlockProviderResponse> BackwardBlockProvider::get() {
    if (finished_) {
        co_return BlockProviderResponse{0, false, false};
    }

    if (is_first_) {
        is_first_ = false;

        auto chunk_loc_res = co_await chunk_locator_.get(max_block_);
        chunk_provider_ = chunk_loc_res.chunk_provider;

        if (chunk_loc_res.error) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, true};
        }

        if (!chunk_loc_res.ok) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, false};
        }

        auto chunk_provider_res = co_await chunk_provider_.get();

        if (chunk_provider_res.error) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, true};
        }

        if (!chunk_provider_res.ok) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, false};
        }

        try {
            roaring::Roaring64Map bitmap = bitmap::parse(chunk_provider_res.chunk);

            // It can happen that on the first chunk we'll get a chunk that contains
            // the last block <= max_block_ in the middle of the chunk/bitmap, so we
            // remove all blocks after it (since there is no AdvanceIfNeeded() in
            // IntIterable64)
            if (max_block_ != std::numeric_limits<uint64_t>::max()) {
                bitmap.removeRange(max_block_ + 1, std::numeric_limits<uint64_t>::max());
            }

            reverse_iterator(bitmap);

            if (!has_next()) {
                chunk_provider_res = co_await chunk_provider_.get();

                if (chunk_provider_res.error) {
                    finished_ = true;
                    co_return BlockProviderResponse{0, false, true};
                }

                if (!chunk_provider_res.ok) {
                    finished_ = true;
                    co_return BlockProviderResponse{0, false, false};
                }

                bitmap = bitmap::parse(chunk_provider_res.chunk);
                reverse_iterator(bitmap);
            }

        } catch (std::exception& e) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, true};
        }
    }

    BlockNum next_block = next();
    bool next = has_next();

    if (!next) {
        auto chunk_provider_res = co_await chunk_provider_.get();

        if (chunk_provider_res.error) {
            co_return BlockProviderResponse{0, false, true};
        }

        if (!chunk_provider_res.ok) {
            finished_ = true;
            co_return BlockProviderResponse{next_block, false, false};
        }

        next = true;

        try {
            auto bitmap = bitmap::parse(chunk_provider_res.chunk);
            reverse_iterator(bitmap);

        } catch (std::exception& e) {
            finished_ = true;
            co_return BlockProviderResponse{0, false, true};
        }
    }

    co_return BlockProviderResponse{next_block, next, false};
}

bool BackwardBlockProvider::has_next() {
    return bitmap_index_ < bitmap_vector_.size();
}

uint64_t BackwardBlockProvider::next() {
    uint64_t result = bitmap_vector_.at(bitmap_index_);
    ++bitmap_index_;
    return result;
}

void BackwardBlockProvider::reverse_iterator(roaring::Roaring64Map& bitmap) {
    bitmap_vector_.resize(bitmap.cardinality());
    bitmap.toUint64Array(bitmap_vector_.data());
    std::reverse(bitmap_vector_.begin(), bitmap_vector_.end());
    bitmap_index_ = 0;
}

Task<BlockProviderResponse> FromToBlockProvider::get() {
    if (!initialized_) {
        initialized_ = true;

        auto from_prov_res = co_await call_from_provider_->get();
        if (from_prov_res.error) {
            co_return BlockProviderResponse{0, false, true};
        }
        next_from_ = from_prov_res.block_num;
        has_more_from_ = from_prov_res.has_more || next_from_ != 0;

        auto to_prov_res = co_await call_to_provider_->get();
        if (to_prov_res.error) {
            co_return BlockProviderResponse{0, false, true};
        }
        next_to_ = to_prov_res.block_num;
        has_more_to_ = to_prov_res.has_more || next_to_ != 0;
    }

    if (!has_more_from_ && !has_more_to_) {
        co_return BlockProviderResponse{0, false, true};
    }

    BlockNum block_num{0};

    if (!has_more_from_) {
        block_num = next_to_;
    } else if (!has_more_to_) {
        block_num = next_from_;
    } else {
        block_num = next_from_;
        if (is_backwards_) {
            if (next_to_ < next_from_) {
                block_num = next_to_;
            }
        } else {
            if (next_to_ > next_from_) {
                block_num = next_to_;
            }
        }
    }

    // Pull next; it may be that from AND to contains the same blockNum
    if (has_more_from_ && block_num == next_from_) {
        auto from_prov_res = co_await call_from_provider_->get();

        if (from_prov_res.error) {
            co_return BlockProviderResponse{0, false, true};
        }
        next_from_ = from_prov_res.block_num;
        has_more_from_ = from_prov_res.has_more || next_from_ != 0;
    }

    if (has_more_to_ && block_num == next_to_) {
        auto to_prov_res = co_await call_to_provider_->get();

        if (to_prov_res.error) {
            co_return BlockProviderResponse{0, false, true};
        }

        next_to_ = to_prov_res.block_num;
        has_more_to_ = to_prov_res.has_more || next_to_ != 0;
    }

    co_return BlockProviderResponse{block_num, has_more_from_ || has_more_to_, false};
}

FromToBlockProvider::FromToBlockProvider(bool is_backwards, BlockProvider* callFromProvider, BlockProvider* callToProvider)
    : is_backwards_{is_backwards},
      call_from_provider_{callFromProvider},
      call_to_provider_{callToProvider} {
}

}  // namespace silkworm::rpc::commands
