// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "txpool_api.hpp"

#include <string>
#include <utility>

#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#txpool_status
Task<void> TxPoolRpcApi::handle_txpool_status(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto status = co_await tx_pool_->get_status();
        TxPoolStatusInfo txpool_status{status.base_fee_count, status.pending_count, status.queued_count};
        reply = make_json_content(request, txpool_status);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://geth.ethereum.org/docs/rpc/ns-txpool
Task<void> TxPoolRpcApi::handle_txpool_content(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto txpool_transactions = co_await tx_pool_->get_transactions();
        TransactionContent transactions_content;
        transactions_content["queued"];
        transactions_content["pending"];
        transactions_content["baseFee"];

        bool error = false;
        for (size_t i{0}; i < txpool_transactions.size(); ++i) {
            ByteView from{txpool_transactions[i].rlp};
            std::string sender = address_to_hex(txpool_transactions[i].sender);
            Transaction txn{};
            const auto result = rlp::decode_transaction(from, txn, rlp::Eip2718Wrapping::kBoth);
            if (!result) {
                SILK_ERROR << "handle_txpool_content rlp::decode_transaction failed sender: " << sender;
                error = true;
                break;
            }
            txn.queued_in_pool = true;
            if (txpool_transactions[i].transaction_type == txpool::TransactionType::kQueued) {
                transactions_content["queued"][sender].insert(std::make_pair(std::to_string(txn.nonce), txn));
            } else if (txpool_transactions[i].transaction_type == txpool::TransactionType::kPending) {
                transactions_content["pending"][sender].insert(std::make_pair(std::to_string(txn.nonce), txn));
            } else {
                transactions_content["baseFee"][sender].insert(std::make_pair(std::to_string(txn.nonce), txn));
            }
        }

        if (!error) {
            reply = make_json_content(request, transactions_content);
        } else {
            reply = make_json_error(request, kInternalError, "RLP decoding error");
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kInternalError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

}  // namespace silkworm::rpc::commands
