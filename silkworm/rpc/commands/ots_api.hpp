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

#include <nlohmann/json.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/db/mdbx/bitmap.hpp>
#include <silkworm/db/remote/kv/api/endpoint/cursor.hpp>
#include <silkworm/db/remote/kv/api/endpoint/key_value.hpp>
#include <silkworm/db/remote/kv/api/state_cache.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/ethbackend/backend.hpp>
#include <silkworm/rpc/ethdb/database.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/types/log.hpp>

namespace silkworm::rpc::json_rpc {
class RequestHandler;
}

namespace silkworm::rpc::commands {

struct ChunkProviderResponse {
    Bytes chunk;
    bool ok;
    bool error;
};

using db::kv::api::KeyValue;
using db::kv::api::StateCache;

class ChunkProvider {
  private:
    db::kv::api::Cursor* cursor_ = nullptr;
    evmc::address address_;
    bool navigate_forward_ = false;
    KeyValue first_seek_key_value_;

    bool first_ = true;
    bool eof_ = false;
    bool error_ = false;

  public:
    ChunkProvider() = default;
    ChunkProvider(db::kv::api::Cursor* cursor, const evmc::address& address, bool navigate_forward, KeyValue first_seek_key_value);

    Task<ChunkProviderResponse> get();
};

struct ChunkLocatorResponse {
    ChunkProvider chunk_provider;
    bool ok{false};
    bool error{false};
};

class ChunkLocator {
  private:
    db::kv::api::Cursor* cursor_;
    evmc::address address_;
    bool navigate_forward_;

  public:
    ChunkLocator(db::kv::api::Cursor* cursor, const evmc::address& address, bool navigate_forward);

    Task<ChunkLocatorResponse> get(BlockNum min_block);
};

struct BlockProviderResponse {
    BlockNum block_number{0};
    bool has_more{false};
    bool error{false};
};

class BlockProvider {
  public:
    virtual ~BlockProvider() = default;
    virtual Task<BlockProviderResponse> get() = 0;
};

class ForwardBlockProvider : public BlockProvider {
  private:
    db::kv::api::Cursor* cursor_;
    evmc::address address_;
    BlockNum min_block_;
    ChunkLocator chunk_locator_;

    bool is_first_{true};
    bool finished_{false};

    ChunkProvider chunk_provider_;
    std::vector<uint64_t> bitmap_vector_;

    uint64_t bitmap_index_{0};

    bool has_next();

    BlockNum next();

    void iterator(roaring::Roaring64Map& bitmap);

    void advance_if_needed(BlockNum min_block);

  public:
    ForwardBlockProvider(db::kv::api::Cursor* cursor, const evmc::address& address, BlockNum min_block) : chunk_locator_(cursor, address, true), chunk_provider_() {
        cursor_ = cursor;
        address_ = address;
        min_block_ = min_block;
    }

    Task<BlockProviderResponse> get() override;
};

class BackwardBlockProvider : public BlockProvider {
  private:
    db::kv::api::Cursor* cursor_;
    evmc::address address_;
    BlockNum max_block_;
    ChunkLocator chunk_locator_;

    bool is_first_{true};
    bool finished_{false};

    ChunkProvider chunk_provider_;
    std::vector<uint64_t> bitmap_vector_;

    uint64_t bitmap_index_{0};

    bool has_next();

    uint64_t next();

    void reverse_iterator(roaring::Roaring64Map& bitmap);

  public:
    BackwardBlockProvider(db::kv::api::Cursor* cursor, const evmc::address& address, BlockNum max_block) : chunk_locator_(cursor, address, false), chunk_provider_() {
        cursor_ = cursor;
        address_ = address;
        max_block_ = max_block;

        if (max_block_ == 0) {
            max_block_ = std::numeric_limits<BlockNum>::max();
        }
    }

    Task<BlockProviderResponse> get() override;
};

class FromToBlockProvider : public BlockProvider {
  private:
    bool is_backwards_{false};
    BlockProvider* callFromProvider_{nullptr};
    BlockProvider* callToProvider_{nullptr};

    uint64_t next_from_{0};
    uint64_t next_to_{0};
    bool has_more_from_{false};
    bool has_more_to_{false};
    bool initialized_{false};

  public:
    FromToBlockProvider(bool is_backwards, BlockProvider* callFromProvider, BlockProvider* callToProvider);

    Task<BlockProviderResponse> get() override;
};

inline constexpr int kMaxPageSize = 25;

class OtsRpcApi {
  public:
    OtsRpcApi(boost::asio::io_context& io_context, WorkerPool& workers)
        : io_context_(io_context),
          workers_{workers},
          database_(must_use_private_service<ethdb::Database>(io_context_)),
          state_cache_(must_use_shared_service<StateCache>(io_context_)),
          block_cache_(must_use_shared_service<BlockCache>(io_context_)),
          backend_{must_use_private_service<ethbackend::BackEnd>(io_context_)} {}

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

    boost::asio::io_context& io_context_;
    WorkerPool& workers_;
    ethdb::Database* database_;
    StateCache* state_cache_;
    BlockCache* block_cache_;
    ethbackend::BackEnd* backend_;

    friend class silkworm::rpc::json_rpc::RequestHandler;

  private:
    Task<bool> trace_blocks(
        FromToBlockProvider& from_to_provider,
        db::kv::api::Transaction& tx,
        const evmc::address& address,
        uint64_t page_size,
        uint64_t result_count,
        std::vector<TransactionsWithReceipts>& results);

    Task<void> trace_block(db::kv::api::Transaction& tx, BlockNum block_number, const evmc::address& search_addr, TransactionsWithReceipts& results);
    static IssuanceDetails get_issuance(const silkworm::ChainConfig& chain_config, const silkworm::BlockWithHash& block);
    static intx::uint256 get_block_fees(const silkworm::BlockWithHash& block, const std::vector<Receipt>& receipts);
};

}  // namespace silkworm::rpc::commands
