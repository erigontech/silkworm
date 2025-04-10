// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <nlohmann/json.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/db/chain/providers.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/db/kv/api/endpoint/key_value.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

using db::kv::api::KeyValue;
using db::kv::api::StateCache;

class OtsRpcApi {
  public:
    OtsRpcApi(boost::asio::io_context& ioc, WorkerPool& workers)
        : ioc_{ioc},
          workers_{workers},
          database_{must_use_private_service<db::kv::api::Client>(ioc_)->service()},
          state_cache_{must_use_shared_service<StateCache>(ioc_)},
          block_cache_{must_use_shared_service<BlockCache>(ioc_)} {}

    virtual ~OtsRpcApi() = default;

    OtsRpcApi(const OtsRpcApi&) = delete;
    OtsRpcApi& operator=(const OtsRpcApi&) = delete;
    OtsRpcApi(OtsRpcApi&&) = default;

  protected:
    Task<void> handle_ots_get_api_level(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_has_code(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_get_block_details(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_get_block_details_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_get_block_transactions(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_get_transaction_by_sender_and_nonce(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_get_contract_creator(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_trace_transaction(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_get_transaction_error(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_get_internal_operations(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_search_transactions_before(const nlohmann::json& request, nlohmann::json& reply);
    Task<void> handle_ots_search_transactions_after(const nlohmann::json& request, nlohmann::json& reply);

    boost::asio::io_context& ioc_;
    WorkerPool& workers_;
    std::shared_ptr<db::kv::api::Service> database_;
    StateCache* state_cache_;
    BlockCache* block_cache_;

    friend class silkworm::rpc::json_rpc::RequestHandler;

  private:
    static IssuanceDetails get_issuance(const silkworm::ChainConfig& chain_config, const silkworm::BlockWithHash& block);
    static intx::uint256 get_block_fees(const std::vector<Receipt>& receipts);

    Task<TransactionsWithReceipts> collect_transactions_with_receipts(
        db::kv::api::Transaction& tx,
        const std::shared_ptr<db::chain::ChainStorage>& chain_storage,
        db::chain::CanonicalBodyForStorageProvider& provider,
        BlockNum block_num_param,
        const evmc::address& address,
        db::kv::api::Timestamp from_timestamp,
        bool ascending,
        uint64_t page_size);
};

}  // namespace silkworm::rpc::commands
