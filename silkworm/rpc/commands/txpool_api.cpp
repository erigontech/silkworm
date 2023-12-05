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

#include "txpool_api.hpp"

#include <string>
#include <utility>

#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#txpool_status
Task<void> TxPoolRpcApi::handle_txpool_status(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto status = co_await tx_pool_->get_status();
        TxPoolStatusInfo txpool_status{status.base_fee_count, status.pending_count, status.queued_count};
        reply = make_json_content(request, txpool_status);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_return;
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
        for (std::size_t i{0}; i < txpool_transactions.size(); i++) {
            silkworm::ByteView from{txpool_transactions[i].rlp};
            std::string sender = address_to_hex(txpool_transactions[i].sender);
            Transaction txn{};
            const auto result = silkworm::rlp::decode_transaction(from, txn, rlp::Eip2718Wrapping::kBoth);
            if (!result) {
                SILK_ERROR << "handle_txpool_content  rlp::decode failed sender: " << sender;
                error = true;
                break;
            }
            txn.queued_in_pool = true;
            if (txpool_transactions[i].transaction_type == txpool::TransactionType::QUEUED) {
                transactions_content["queued"][sender].insert(std::make_pair(std::to_string(txn.nonce), txn));
            } else if (txpool_transactions[i].transaction_type == txpool::TransactionType::PENDING) {
                transactions_content["pending"][sender].insert(std::make_pair(std::to_string(txn.nonce), txn));
            } else {
                transactions_content["baseFee"][sender].insert(std::make_pair(std::to_string(txn.nonce), txn));
            }
        }

        if (!error) {
            reply = make_json_content(request, transactions_content);
        } else {
            reply = make_json_error(request, 100, "RLP decoding error");
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_return;
}

}  // namespace silkworm::rpc::commands
