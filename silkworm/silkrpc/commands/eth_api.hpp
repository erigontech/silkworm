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

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/silkrpc/core/filter_storage.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethbackend/backend.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/kv/state_cache.hpp>
#include <silkworm/silkrpc/ethdb/transaction.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/txpool/miner.hpp>
#include <silkworm/silkrpc/txpool/transaction_pool.hpp>
#include <silkworm/silkrpc/types/filter.hpp>
#include <silkworm/silkrpc/types/log.hpp>
#include <silkworm/silkrpc/types/receipt.hpp>

namespace silkworm::http {
class RequestHandler;
}

namespace silkworm::rpc::commands {

class EthereumRpcApi {
  public:
    EthereumRpcApi(boost::asio::io_context& io_context, boost::asio::thread_pool& workers)
        : io_context_{io_context},
          block_cache_{must_use_shared_service<BlockCache>(io_context_)},
          state_cache_{must_use_shared_service<ethdb::kv::StateCache>(io_context_)},
          database_{must_use_private_service<ethdb::Database>(io_context_)},
          backend_{must_use_private_service<ethbackend::BackEnd>(io_context_)},
          miner_{must_use_private_service<txpool::Miner>(io_context_)},
          tx_pool_{must_use_private_service<txpool::TransactionPool>(io_context_)},
          filter_storage_{must_use_shared_service<FilterStorage>(io_context_)},
          workers_{workers} {}

    virtual ~EthereumRpcApi() = default;

    EthereumRpcApi(const EthereumRpcApi&) = delete;
    EthereumRpcApi& operator=(const EthereumRpcApi&) = delete;

  protected:
    Task<void> handle_eth_block_number(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_chain_id(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_protocol_version(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_syncing(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_gas_price(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_block_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_block_transaction_count_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_block_transaction_count_by_number(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_uncle_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_uncle_by_block_number_and_index(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_uncle_count_by_block_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_uncle_count_by_block_number(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_transaction_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_transaction_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_transaction_by_block_number_and_index(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_raw_transaction_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_raw_transaction_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_raw_transaction_by_block_number_and_index(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_transaction_receipt(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_estimate_gas(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_balance(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_code(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_transaction_count(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_storage_at(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_call_bundle(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_create_access_list(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_new_filter(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_new_block_filter(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_new_pending_transaction_filter(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_filter_logs(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_filter_changes(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_uninstall_filter(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_send_raw_transaction(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_send_transaction(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_sign_transaction(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_proof(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_mining(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_coinbase(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_hashrate(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_submit_hashrate(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_work(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_submit_work(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_subscribe(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_unsubscribe(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_max_priority_fee_per_gas(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_fee_history(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_call_many(const nlohmann::json& request, nlohmann::json& reply);

    // GLAZE format routine
    Task<void> handle_eth_get_logs(const nlohmann::json& request, std::string& reply);
    Task<void> handle_eth_call(const nlohmann::json& request, std::string& reply);
    Task<void> handle_eth_get_block_by_number(const nlohmann::json& request, std::string& reply);

    boost::asio::io_context& io_context_;
    BlockCache* block_cache_;
    ethdb::kv::StateCache* state_cache_;
    ethdb::Database* database_;
    ethbackend::BackEnd* backend_;
    txpool::Miner* miner_;
    txpool::TransactionPool* tx_pool_;
    FilterStorage* filter_storage_;
    boost::asio::thread_pool& workers_;

    friend class silkworm::http::RequestHandler;
};

}  // namespace silkworm::rpc::commands
