// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/core/filter_storage.hpp>
#include <silkworm/rpc/ethbackend/backend.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/txpool/miner.hpp>
#include <silkworm/rpc/txpool/transaction_pool.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

using db::kv::api::StateCache;

class EthereumRpcApi {
  public:
    EthereumRpcApi(boost::asio::io_context& ioc, WorkerPool& workers)
        : ioc_{ioc},
          block_cache_{must_use_shared_service<BlockCache>(ioc_)},
          state_cache_{must_use_shared_service<StateCache>(ioc_)},
          database_{must_use_private_service<db::kv::api::Client>(ioc_)->service()},
          backend_{must_use_private_service<ethbackend::BackEnd>(ioc_)},
          miner_{must_use_private_service<txpool::Miner>(ioc_)},
          tx_pool_{must_use_private_service<txpool::TransactionPool>(ioc_)},
          filter_storage_{must_use_shared_service<FilterStorage>(ioc_)},
          workers_{workers} {}

    virtual ~EthereumRpcApi() = default;

    EthereumRpcApi(const EthereumRpcApi&) = delete;
    EthereumRpcApi& operator=(const EthereumRpcApi&) = delete;
    EthereumRpcApi(EthereumRpcApi&&) = default;

  protected:
    Task<void> handle_eth_block_num(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_chain_id(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_protocol_version(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_syncing(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_gas_price(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_block_transaction_count_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_block_transaction_count_by_number(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_uncle_count_by_block_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_uncle_count_by_block_num(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_transaction_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_transaction_by_block_num_and_index(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_raw_transaction_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_raw_transaction_by_block_hash_and_index(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_raw_transaction_by_block_num_and_index(const nlohmann::json& request, nlohmann::json& reply);
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
    Task<void> handle_eth_fee_history(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_call_many(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_blob_base_fee(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_base_fee(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_eth_get_block_receipts(const nlohmann::json& request, nlohmann::json& reply);

    // GLAZE format routine
    Task<void> handle_eth_get_logs(const nlohmann::json& request, std::string& reply);
    Task<void> handle_eth_call(const nlohmann::json& request, std::string& reply);
    Task<void> handle_eth_get_block_by_number(const nlohmann::json& request, std::string& reply);
    Task<void> handle_eth_get_block_by_hash(const nlohmann::json& request, std::string& reply);
    Task<void> handle_eth_get_uncle_by_block_hash_and_index(const nlohmann::json& request, std::string& reply);
    Task<void> handle_eth_get_uncle_by_block_num_and_index(const nlohmann::json& request, std::string& reply);
    Task<void> handle_eth_get_transaction_by_hash(const nlohmann::json& request, std::string& reply);

    boost::asio::io_context& ioc_;
    BlockCache* block_cache_;
    StateCache* state_cache_;
    std::shared_ptr<db::kv::api::Service> database_;
    ethbackend::BackEnd* backend_;
    txpool::Miner* miner_;
    txpool::TransactionPool* tx_pool_;
    FilterStorage* filter_storage_;
    WorkerPool& workers_;

    friend class silkworm::rpc::json_rpc::RequestHandler;
};

}  // namespace silkworm::rpc::commands
