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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/thread_pool.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/silkrpc/ethbackend/backend.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/kv/state_cache.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/types/log.hpp>

namespace silkworm::http {
class RequestHandler;
}

namespace silkworm::rpc::commands {

struct ChunkProviderResponse {
    Bytes chunk;
    bool ok;
    bool error;
};

class ChunkProvider {
  private:
    silkworm::rpc::ethdb::Cursor* cursor_;
    evmc::address address_;
    bool navigate_forward_;
    silkworm::KeyValue first_seek_key_value_;

    bool first_ = true;
    bool eof_ = false;
    bool error_ = false;

  public:
    ChunkProvider() {}
    ChunkProvider(silkworm::rpc::ethdb::Cursor* cursor, evmc::address address, bool navigate_forward, silkworm::KeyValue first_seek_key_value);

    boost::asio::awaitable<ChunkProviderResponse> get();
};

struct ChunkLocatorResponse {
    ChunkProvider chunk_provider;
    bool ok;
    bool error;
};

class ChunkLocator {
  private:
    silkworm::rpc::ethdb::Cursor* cursor_;
    evmc::address address_;
    bool navigate_forward_;

  public:
    ChunkLocator(silkworm::rpc::ethdb::Cursor* cursor, evmc::address address, bool navigate_forward);

    boost::asio::awaitable<ChunkLocatorResponse> get(uint64_t min_block);
};

struct BlockProviderResponse {
    uint64_t block_number;
    bool has_more;
    bool error;
};

class BlockProvider {
  public:
    virtual ~BlockProvider() {}
    virtual boost::asio::awaitable<BlockProviderResponse> get() = 0;
};

class ForwardBlockProvider : public BlockProvider {
  private:
    silkworm::rpc::ethdb::Cursor* cursor_;
    evmc::address address_;
    uint64_t min_block_;
    ChunkLocator chunk_locator_;

    bool is_first_;
    bool finished_;

    ChunkProvider chunk_provider_;
    std::vector<uint64_t> bitmap_vector_;

    uint64_t bitmap_index_;

    bool has_next();

    uint64_t next();

    void iterator(roaring::Roaring64Map& bitmap);

    void advance_if_needed(uint64_t min_block);

  public:
    ForwardBlockProvider(silkworm::rpc::ethdb::Cursor* cursor, evmc::address address, uint64_t min_block) : chunk_locator_(cursor, address, false), chunk_provider_() {
        cursor_ = cursor;
        address_ = address;
        min_block_ = min_block;

        is_first_ = true;
        finished_ = false;
    }

    boost::asio::awaitable<BlockProviderResponse> get();
};

class BackwardBlockProvider : public BlockProvider {
  private:
    silkworm::rpc::ethdb::Cursor* cursor_;
    evmc::address address_;
    uint64_t max_block_;
    ChunkLocator chunk_locator_;

    bool is_first_;
    bool finished_;

    ChunkProvider chunk_provider_;
    std::vector<uint64_t> bitmap_vector_;

    uint64_t bitmap_index_;

    bool has_next();

    uint64_t next();

    void reverse_iterator(roaring::Roaring64Map& bitmap);

  public:
    BackwardBlockProvider(silkworm::rpc::ethdb::Cursor* cursor, evmc::address address, uint64_t max_block) : chunk_locator_(cursor, address, false), chunk_provider_() {
        cursor_ = cursor;
        address_ = address;
        max_block_ = max_block;

        if (max_block_ == 0) {
            max_block_ = std::numeric_limits<uint64_t>::max();
        }

        is_first_ = true;
        finished_ = false;
    }

    boost::asio::awaitable<BlockProviderResponse> get();
};

class FromToBlockProvider : public BlockProvider {
  private:
    bool is_backwards_;
    BlockProvider* callFromProvider_;
    BlockProvider* callToProvider_;

    uint64_t next_from_;
    uint64_t next_to_;
    bool has_more_from_;
    bool has_more_to_;
    bool initialized_;

  public:
    FromToBlockProvider(bool is_backwards, BlockProvider* callFromProvider, BlockProvider* callToProvider);

    boost::asio::awaitable<BlockProviderResponse> get();
};

class OtsRpcApi {
  public:
    OtsRpcApi(boost::asio::io_context& io_context, boost::asio::thread_pool& workers)
        : io_context_(io_context),
          workers_{workers},
          database_(must_use_private_service<ethdb::Database>(io_context_)),
          state_cache_(must_use_shared_service<ethdb::kv::StateCache>(io_context_)),
          block_cache_(must_use_shared_service<BlockCache>(io_context_)) {}
    virtual ~OtsRpcApi() = default;

    OtsRpcApi(const OtsRpcApi&) = delete;
    OtsRpcApi& operator=(const OtsRpcApi&) = delete;

  protected:
    boost::asio::awaitable<void> handle_ots_get_api_level(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_has_code(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_block_details(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_block_details_by_hash(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_block_transactions(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_transaction_by_sender_and_nonce(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_contract_creator(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_trace_transaction(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_transaction_error(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_get_internal_operations(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_search_transactions_before(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_ots_search_transactions_after(const nlohmann::json& request, nlohmann::json& reply);

    boost::asio::io_context& io_context_;
    boost::asio::thread_pool& workers_;
    ethdb::Database* database_;
    ethdb::kv::StateCache* state_cache_;
    BlockCache* block_cache_;
    friend class silkworm::http::RequestHandler;

  private:
    boost::asio::awaitable<bool> trace_blocks(FromToBlockProvider& from_to_provider,
                                              ethdb::Transaction& tx,
                                              evmc::address address,
                                              uint64_t page_size,
                                              uint64_t result_count,
                                              std::vector<TransactionsWithReceipts>& results);

    boost::asio::awaitable<void> search_trace_block(ethdb::Transaction& tx, evmc::address address, unsigned long index, uint64_t block_number, std::vector<TransactionsWithReceipts>& results);
    boost::asio::awaitable<void> trace_block(ethdb::Transaction& tx, uint64_t block_number, evmc::address search_addr, TransactionsWithReceipts& results);
    static IssuanceDetails get_issuance(const ChainConfig& chain_config, const silkworm::BlockWithHash& block);
    static intx::uint256 get_block_fees(const ChainConfig& chain_config, const silkworm::BlockWithHash& block,
                                        std::vector<Receipt>& receipts, silkworm::BlockNum block_number);
};

}  // namespace silkworm::rpc::commands
