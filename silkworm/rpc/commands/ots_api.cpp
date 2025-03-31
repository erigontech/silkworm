// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ots_api.hpp"

#include <numeric>
#include <string>
#include <utility>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/protocol/ethash_rule_set.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/chain/providers.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/kv/api/endpoint/key_value.hpp>
#include <silkworm/db/kv/state_reader.hpp>
#include <silkworm/db/kv/txn_num.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/async_binary_search.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/evm_trace.hpp>
#include <silkworm/rpc/core/receipts.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::rpc::commands {

using namespace silkworm::db;
using db::kv::StateReader;
namespace bitmap {
    using namespace silkworm::datastore::kvdb::bitmap;
}

//! The current supported version of the Otterscan API
static constexpr int kCurrentApiLevel{8};

//! The window size used when probing history periodically
static constexpr uint64_t kTxnProbeWindowSize{4096};

//! The maximum allowed page size for the Otterscan API
static constexpr int kMaxPageSize{25};

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
        const BlockReader block_reader{*chain_storage, *tx};

        // Check if target block is the latest one: use local state cache (if any) for target transaction
        const bool is_latest_block = co_await block_reader.is_latest_block_num(BlockNumOrHash{block_id});

        std::optional<TxnId> txn_id;
        if (!is_latest_block) {
            const auto block_num = co_await block_reader.get_block_num(block_id);
            txn_id = co_await tx->user_txn_id_at(block_num + 1);
        }

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
        const BlockReader block_reader{*chain_storage, *tx};

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
        const BlockReader block_reader{*chain_storage, *tx};

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

        db::kv::api::IndexRangeRequest query{
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
            db::kv::api::HistoryPointRequest hpq{
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
            db::kv::api::HistoryPointRequest hpq{
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

        const auto chain_storage = tx->create_storage();
        auto canonical_body_provider = db::chain::canonical_body_provider_from_chain_storage(*chain_storage);
        const auto block_num_opt = co_await db::txn::block_num_from_tx_num(*tx, creation_txn_id, canonical_body_provider);
        if (block_num_opt) {
            const auto block_num = block_num_opt.value();
            const auto min_txn_id = co_await db::txn::min_tx_num(*tx, block_num, canonical_body_provider);
            const auto first_txn_id = co_await tx->first_txn_num_in_block(block_num);
            SILK_DEBUG << "block_num: " << block_num << ", min_txn_id: " << min_txn_id << ", first_txn_id: " << first_txn_id;

            TxnId tx_index{0};
            if (creation_txn_id == min_txn_id) {
                tx_index = index + prev_txn_id - min_txn_id - 1;
            } else {
                tx_index = creation_txn_id - min_txn_id - 1;
            }
            SILK_DEBUG << "block_num: " << block_num << ", tx_index: " << tx_index;

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
        const BlockReader block_reader{*chain_storage, *tx};
        BlockNum block_num = co_await block_reader.get_latest_block_num();
        const auto txn_number = co_await tx->user_txn_id_at(block_num);

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
        db::kv::api::IndexRangeRequest query{
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

            db::kv::api::HistoryPointRequest hpq{
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

            db::kv::api::HistoryPointRequest hpq{
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
        auto canonical_body_provider = db::chain::canonical_body_provider_from_chain_storage(*chain_storage);
        const auto block_num_opt = co_await db::txn::block_num_from_tx_num(*tx, creation_txn_id, canonical_body_provider);
        if (block_num_opt) {
            block_num = block_num_opt.value();
            const auto min_txn_id = co_await db::txn::min_tx_num(*tx, block_num, canonical_body_provider);
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
        SILK_DEBUG << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    if (block_num > 0) {
        --block_num;
    }
    auto tx = co_await database_->begin_transaction();
    try {
        const auto chain_storage = tx->create_storage();
        auto canonical_body_provider = db::chain::canonical_body_provider_from_chain_storage(*chain_storage);

        db::kv::api::Timestamp from_timestamp{-1};
        if (block_num > 0) {
            const auto max_tx_num = co_await db::txn::max_tx_num(*tx, block_num, canonical_body_provider);
            from_timestamp = static_cast<db::kv::api::Timestamp>(max_tx_num);
            SILK_DEBUG << "block_num: " << block_num << " max_tx_num: " << max_tx_num;
        }

        const TransactionsWithReceipts results = co_await collect_transactions_with_receipts(
            *tx, chain_storage, canonical_body_provider, block_num, address, from_timestamp, /*ascending=*/false, page_size);

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
        SILK_DEBUG << error_msg;
        reply = make_json_error(request, kServerError, error_msg);
        co_return;
    }

    auto tx = co_await database_->begin_transaction();

    try {
        const auto chain_storage = tx->create_storage();
        auto canonical_body_provider = db::chain::canonical_body_provider_from_chain_storage(*chain_storage);

        db::kv::api::Timestamp from_timestamp{-1};
        if (block_num > 0) {
            const auto max_tx_num = co_await db::txn::min_tx_num(*tx, block_num + 1, canonical_body_provider);
            from_timestamp = static_cast<db::kv::api::Timestamp>(max_tx_num);
            SILK_DEBUG << "block_num: " << block_num << " max_tx_num: " << max_tx_num;
        }

        TransactionsWithReceipts results = co_await collect_transactions_with_receipts(
            *tx, chain_storage, canonical_body_provider, block_num, address, from_timestamp, /*ascending=*/true, page_size);

        std::ranges::reverse(results.transactions);
        std::ranges::reverse(results.receipts);
        std::ranges::reverse(results.headers);

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
    const std::shared_ptr<db::chain::ChainStorage>& chain_storage,
    db::chain::CanonicalBodyForStorageProvider& provider,
    BlockNum block_num_param,
    const evmc::address& address,
    db::kv::api::Timestamp from_timestamp,
    bool ascending, uint64_t page_size) {
    const auto key = db::code_domain_key(address);
    db::kv::api::IndexRangeRequest query_to{
        .table = db::table::kTracesToIdx,
        .key = key,
        .from_timestamp = from_timestamp,
        .to_timestamp = -1,
        .ascending_order = ascending};
    auto paginated_result_to = co_await tx.index_range(std::move(query_to));

    db::kv::api::IndexRangeRequest query_from{
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

    silkworm::Block block;
    std::optional<BlockHeader> header;

    while (const auto tnx_nums = co_await txn_nums_it->next()) {
        SILK_DEBUG << "txn_id: " << tnx_nums->txn_id << " block_num: " << tnx_nums->block_num
                   << ", tnx_index: " << (tnx_nums->txn_index ? std::to_string(*tnx_nums->txn_index) : "")
                   << ", ascending: " << std::boolalpha << ascending;

        if (tnx_nums->block_changed) {
            block_info.reset();

            // Even if the desired page size is reached, drain the entire matching txs inside the block to reproduce E2
            // behavior. An E3 paginated-aware ots spec could improve in this area.
            if (results.transactions.size() >= page_size) {
                if (ascending) {
                    results.first_page = false;
                } else {
                    results.last_page = false;
                }
                break;
            }
        }

        if (!tnx_nums->txn_index) {
            continue;
        }

        if (tnx_nums->block_changed) {
            header = co_await chain_storage->read_canonical_header(tnx_nums->block_num);
            if (!header) {
                SILK_DEBUG << "Not found header no.  " << tnx_nums->block_num;
                break;
            }
            block.header = std::move(*header);
        }

        SILKWORM_ASSERT(header);

        const auto transaction = co_await chain_storage->read_transaction_by_idx_in_block(tnx_nums->block_num, tnx_nums->txn_index.value());
        if (!transaction) {
            SILK_DEBUG << "No transaction found in block " << tnx_nums->block_num << " for index " << tnx_nums->txn_index.value();
            continue;
        }

        auto receipt = co_await core::get_receipt(tx, block, tnx_nums->txn_id, tnx_nums->txn_index.value(), *transaction, *chain_storage, workers_);
        if (!receipt) {
            SILK_DEBUG << "No receipt found in block " << tnx_nums->block_num << " for index " << tnx_nums->txn_index.value();
            continue;
        }

        results.receipts.push_back(std::move(*receipt));
        results.transactions.push_back(std::move(*transaction));
        results.headers.push_back(block.header);
    }

    SILK_DEBUG << "Results transactions size: " << results.transactions.size() << " receipts size: " << results.receipts.size();

    co_return results;
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

        intx::uint256 base_fee = block.block.header.base_fee_per_gas.value_or(0);
        const auto effective_gas_price = txn.effective_gas_price(base_fee);

        fees += effective_gas_price * receipt.gas_used;
    }
    return fees;
}

}  // namespace silkworm::rpc::commands
