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

    bool first = true;
    bool eof = false;
    bool error = false;

  public:
    ChunkProvider() {}
    ChunkProvider(silkworm::rpc::ethdb::Cursor* cursor, evmc::address address, bool navigate_forward, silkworm::KeyValue first_seek_key_value) {
        cursor_ = cursor;
        address_ = address;
        navigate_forward_ = navigate_forward;
        first_seek_key_value_ = first_seek_key_value;
    }

    boost::asio::awaitable<ChunkProviderResponse> get() {
        if (error) {
            co_return ChunkProviderResponse{Bytes{0}, false, true};
        }

        if (eof) {
            co_return ChunkProviderResponse{Bytes{0}, false, false};
        }

        silkworm::KeyValue key_value;

        try {
            if (first) {
                first = false;
                key_value = first_seek_key_value_;
            } else {
                if (navigate_forward_) {
                    key_value = co_await cursor_->next();
                } else {
                    key_value = co_await cursor_->previous();
                }
            }
        } catch (const std::exception& e) {
            error = true;
        }

        if (error) {
            eof = true;
            co_return ChunkProviderResponse{Bytes{0}, false, true};
        }

        if (key_value.key.empty() || !key_value.key.starts_with(address_)) {
            eof = true;
            co_return ChunkProviderResponse{Bytes{0}, false, false};
        }

        co_return ChunkProviderResponse{key_value.value, true, false};
    }
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
    ChunkLocator(silkworm::rpc::ethdb::Cursor* cursor, evmc::address address, bool navigate_forward) {
        cursor_ = cursor;
        address_ = address;
        navigate_forward_ = navigate_forward;
    }

    boost::asio::awaitable<ChunkLocatorResponse> get(uint64_t min_block) {
        KeyValue key_value;
        try {
            key_value = co_await cursor_->seek(db::account_history_key(address_, min_block));

            if (key_value.key.empty()) {
                co_return ChunkLocatorResponse(ChunkProvider(cursor_, address_, navigate_forward_, key_value), false, false);
            }

            co_return ChunkLocatorResponse(ChunkProvider(cursor_, address_, navigate_forward_, key_value), true, false);

        } catch (const std::exception& e) {
            co_return ChunkLocatorResponse(ChunkProvider(cursor_, address_, navigate_forward_, key_value), false, true);
        }
    }
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

    bool has_next() {
        return bitmap_index_ < bitmap_vector_.size();
    }

    uint64_t next() {
        uint64_t result = bitmap_vector_.at(bitmap_index_);
        bitmap_index_++;
        return result;
    }

    void iterator(roaring::Roaring64Map& bitmap) {
        bitmap_vector_.resize(bitmap.cardinality());
        bitmap.toUint64Array(bitmap_vector_.data());
        bitmap_index_ = 0;
    }

    void advance_if_needed(uint64_t min_block) {
        for (uint64_t i = bitmap_index_; i < bitmap_vector_.size(); i++) {
            if (bitmap_vector_.at(i) >= min_block) {
                bitmap_index_ = i;
                break;
            }
        }
    }

  public:
    ForwardBlockProvider(silkworm::rpc::ethdb::Cursor* cursor, evmc::address address, uint64_t min_block) : chunk_locator_(cursor, address, false), chunk_provider_() {
        cursor_ = cursor;
        address_ = address;
        min_block_ = min_block;

        is_first_ = true;
        finished_ = false;
    }

    boost::asio::awaitable<BlockProviderResponse> get() {
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

            auto chunk_provider_res = co_await chunk_loc_res.chunk_provider.get();

            if (chunk_provider_res.error) {
                finished_ = true;
                co_return BlockProviderResponse{0, false, true};
            }

            if (!chunk_provider_res.ok) {
                finished_ = true;
                co_return BlockProviderResponse{0, false, false};
            }

            try {
                roaring::Roaring64Map bitmap = db::bitmap::parse(chunk_provider_res.chunk);

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

        uint64_t next_block = next();
        bool has_next_ = has_next();

        if (!has_next_) {
            auto chunk_provider_res = co_await chunk_provider_.get();

            if (chunk_provider_res.error) {
                co_return BlockProviderResponse{0, false, true};
            }

            if (!chunk_provider_res.ok) {
                finished_ = true;
                co_return BlockProviderResponse{next_block, false, false};
            }

            has_next_ = true;

            try {
                auto bitmap = db::bitmap::parse(chunk_provider_res.chunk);
                iterator(bitmap);

            } catch (std::exception& e) {
                finished_ = true;
                co_return BlockProviderResponse{0, false, true};
            }
        }

        co_return BlockProviderResponse{next_block, has_next_, false};
    }
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

    bool has_next() {
        return bitmap_index_ < bitmap_vector_.size();
    }

    uint64_t next() {
        uint64_t result = bitmap_vector_.at(bitmap_index_);
        bitmap_index_++;
        return result;
    }

    void reverse_iterator(roaring::Roaring64Map& bitmap) {
        bitmap_vector_.resize(bitmap.cardinality());
        bitmap.toUint64Array(bitmap_vector_.data());
        std::reverse(bitmap_vector_.begin(), bitmap_vector_.end());
        bitmap_index_ = 0;
    }

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

    boost::asio::awaitable<BlockProviderResponse> get() {
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

            auto chunk_provider_res = co_await chunk_loc_res.chunk_provider.get();

            if (chunk_provider_res.error) {
                finished_ = true;
                co_return BlockProviderResponse{0, false, true};
            }

            if (!chunk_provider_res.ok) {
                finished_ = true;
                co_return BlockProviderResponse{0, false, false};
            }

            try {
                roaring::Roaring64Map bitmap = db::bitmap::parse(chunk_provider_res.chunk);

                // It can happen that on the first chunk we'll get a chunk that contains
                // the last block <= maxBlock in the middle of the chunk/bitmap, so we
                // remove all blocks after it (since there is no AdvanceIfNeeded() in
                // IntIterable64)
                if (max_block_ != std::numeric_limits<uint64_t>::max()) {
                    // bm.RemoveRange(maxBlock+1, MaxBlockNum)
                    bitmap.removeRange(max_block_ + 1, std::numeric_limits<uint64_t>::max());
                }

                reverse_iterator(bitmap);

                if (!has_next()) {
                    chunk_provider_res = co_await chunk_loc_res.chunk_provider.get();

                    if (chunk_provider_res.error) {
                        finished_ = true;
                        co_return BlockProviderResponse{0, false, true};
                    }

                    if (!chunk_provider_res.ok) {
                        finished_ = true;
                        co_return BlockProviderResponse{0, false, false};
                    }

                    bitmap = db::bitmap::parse(chunk_provider_res.chunk);
                    reverse_iterator(bitmap);
                }

            } catch (std::exception& e) {
                finished_ = true;
                co_return BlockProviderResponse{0, false, true};
            }
        }

        uint64_t next_block = next();
        bool has_next_ = has_next();

        if (!has_next_) {
            auto chunk_provider_res = co_await chunk_provider_.get();

            if (chunk_provider_res.error) {
                co_return BlockProviderResponse{0, false, true};
            }

            if (!chunk_provider_res.ok) {
                finished_ = true;
                co_return BlockProviderResponse{next_block, false, false};
            }

            has_next_ = true;

            try {
                auto bitmap = db::bitmap::parse(chunk_provider_res.chunk);
                reverse_iterator(bitmap);

            } catch (std::exception& e) {
                finished_ = true;
                co_return BlockProviderResponse{0, false, true};
            }
        }

        co_return BlockProviderResponse{next_block, has_next_, false};
    }
};

class FromToBlockProvider : public BlockProvider {
  private:
    bool is_backwards_;
    BlockProvider* callFromProvider_;
    BlockProvider* callToProvider_;

    uint64_t next_from;
    uint64_t next_to;
    bool has_more_from;
    bool has_more_to;
    bool initialized_;

  public:
    FromToBlockProvider(bool is_backwards, BlockProvider* callFromProvider, BlockProvider* callToProvider) {
        is_backwards_ = is_backwards;
        callFromProvider_ = callFromProvider;
        callToProvider_ = callToProvider;
        initialized_ = false;
    }

    boost::asio::awaitable<BlockProviderResponse> get() {
        if (!initialized_) {
            initialized_ = true;

            auto from_prov_res = co_await callFromProvider_->get();
            if (from_prov_res.error) {
                co_return BlockProviderResponse{0, false, true};
            }

            auto to_prov_res = co_await callToProvider_->get();
            if (to_prov_res.error) {
                co_return BlockProviderResponse{0, false, true};
            }

            next_from = from_prov_res.block_number;
            next_to = to_prov_res.block_number;

            has_more_from = has_more_from || next_from != 0;
            has_more_to = has_more_to || next_to != 0;
        }

        if (!has_more_from && !has_more_to) {
            co_return BlockProviderResponse{0, false, true};
        }

        uint64_t block_num{0};

        if (!has_more_from) {
            block_num = next_to;
        } else if (!has_more_to) {
            block_num = next_from;
        } else {
            block_num = next_from;
            if (is_backwards_) {
                if (next_to < next_from) {
                    block_num = next_to;
                }
            } else {
                if (next_to > next_from) {
                    block_num = next_to;
                }
            }
        }

        // Pull next; it may be that from AND to contains the same blockNum
        if (has_more_from && block_num == next_from) {
            auto from_prov_res = co_await callFromProvider_->get();

            if (from_prov_res.error) {
                co_return BlockProviderResponse{0, false, true};
            }

            next_from = from_prov_res.block_number;
            has_more_from = has_more_from || next_from != 0;
        }

        if (has_more_to && block_num == next_to) {
            auto to_prov_res = co_await callToProvider_->get();

            if (to_prov_res.error) {
                co_return BlockProviderResponse{0, false, true};
            }

            next_to = to_prov_res.block_number;
            has_more_to = has_more_to || next_to != 0;
        }

        co_return BlockProviderResponse{block_num, has_more_from || has_more_to, false};
    }
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
