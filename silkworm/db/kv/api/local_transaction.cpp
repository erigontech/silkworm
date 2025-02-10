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

#include "local_transaction.hpp"

#include <silkworm/db/chain/local_chain_storage.hpp>
#include <silkworm/db/datastore/inverted_index_range_by_key_query.hpp>
#include <silkworm/db/datastore/kvdb/raw_codec.hpp>
#include <silkworm/db/datastore/snapshots/common/raw_codec.hpp>

namespace silkworm::db::kv::api {

using namespace silkworm::datastore;

Task<void> LocalTransaction::open() {
    co_return;
}

Task<std::shared_ptr<Cursor>> LocalTransaction::cursor(const std::string& table) {
    co_return co_await get_cursor(table, false);
}

Task<std::shared_ptr<CursorDupSort>> LocalTransaction::cursor_dup_sort(const std::string& table) {
    co_return co_await get_cursor(table, true);
}

Task<void> LocalTransaction::close() {
    cursors_.clear();
    co_return;
}

Task<std::shared_ptr<CursorDupSort>> LocalTransaction::get_cursor(const std::string& table, bool is_cursor_dup_sort) {
    if (is_cursor_dup_sort) {
        auto cursor_it = dup_cursors_.find(table);
        if (cursor_it != dup_cursors_.end()) {
            co_return cursor_it->second;
        }
    } else {
        auto cursor_it = cursors_.find(table);
        if (cursor_it != cursors_.end()) {
            co_return cursor_it->second;
        }
    }
    auto cursor = std::make_shared<LocalCursor>(txn_, ++last_cursor_id_);
    co_await cursor->open_cursor(table, is_cursor_dup_sort);
    if (is_cursor_dup_sort) {
        dup_cursors_[table] = cursor;
    } else {
        cursors_[table] = cursor;
    }
    co_return cursor;
}

std::shared_ptr<chain::ChainStorage> LocalTransaction::create_storage() {
    // The calling thread *must* be the *same* which created this LocalTransaction instance
    return std::make_shared<chain::LocalChainStorage>(DataModel{txn_, data_store_.blocks_repository});
}

Task<TxnId> LocalTransaction::first_txn_num_in_block(BlockNum /*block_num*/) {
    throw std::logic_error{"LocalTransaction::first_txn_num_in_block: not yet implemented"};
}

Task<GetLatestResult> LocalTransaction::get_latest(GetLatestQuery /*query*/) {
    // TODO(canepat) implement using E3-like aggregator abstraction [tx_id_ must be changed]
    co_return GetLatestResult{};
}

Task<GetAsOfResult> LocalTransaction::get_as_of(GetAsOfQuery /*query*/) {
    // TODO(canepat) implement using E3-like aggregator abstraction [tx_id_ must be changed]
    co_return GetAsOfResult{};
}

Task<HistoryPointResult> LocalTransaction::history_seek(HistoryPointQuery /*query*/) {
    // TODO(canepat) implement using E3-like aggregator abstraction [tx_id_ must be changed]
    co_return HistoryPointResult{};
}

Task<PaginatedTimestamps> LocalTransaction::index_range(IndexRangeQuery query) {
    // TODO: convert query.table to II EntityName
    datastore::EntityName inverted_index_name = state::kInvIdxNameLogAddress;
    InvertedIndexRangeByKeyQuery<kvdb::RawEncoder<Bytes>, snapshots::RawEncoder<Bytes>> store_query{
        inverted_index_name,
        data_store_.chaindata,
        txn_,
        data_store_.state_repository_historical,
    };

    // TODO: convert query from/to to ts_range
    auto ts_range = datastore::TimestampRange{0, 10};
    size_t limit = (query.limit == kUnlimited) ? std::numeric_limits<size_t>::max() : static_cast<size_t>(query.limit);

    if (query.ascending_order) {
        // TODO: this is just a test example, instead of direct iteration, apply page_size using std::views::chunk,
        // TODO: save the range for future requests using page_token and return the first chunk
        for ([[maybe_unused]] datastore::Timestamp t : store_query.exec<true>(query.key, ts_range) | std::views::take(limit)) {
        }
    } else {
        // TODO: same, this is just a test example
        for ([[maybe_unused]] datastore::Timestamp t : store_query.exec<false>(query.key, ts_range) | std::views::take(limit)) {
        }
    }

    // TODO(canepat) implement using E3-like aggregator abstraction [tx_id_ must be changed]
    auto paginator = [](api::PaginatedTimestamps::PageToken) mutable -> Task<api::PaginatedTimestamps::PageResult> {
        co_return api::PaginatedTimestamps::PageResult{};
    };
    co_return api::PaginatedTimestamps{std::move(paginator)};
}

Task<PaginatedKeysValues> LocalTransaction::history_range(HistoryRangeQuery /*query*/) {
    // TODO(canepat) implement using E3-like aggregator abstraction [tx_id_ must be changed]
    auto paginator = [](api::PaginatedKeysValues::PageToken) mutable -> Task<api::PaginatedKeysValues::PageResult> {
        co_return api::PaginatedKeysValues::PageResult{};
    };
    co_return api::PaginatedKeysValues{std::move(paginator)};
}

Task<PaginatedKeysValues> LocalTransaction::range_as_of(DomainRangeQuery /*query*/) {
    // TODO(canepat) implement using E3-like aggregator abstraction [tx_id_ must be changed]
    auto paginator = [](api::PaginatedKeysValues::PageToken) mutable -> Task<api::PaginatedKeysValues::PageResult> {
        co_return api::PaginatedKeysValues::PageResult{};
    };
    co_return api::PaginatedKeysValues{std::move(paginator)};
}

}  // namespace silkworm::db::kv::api
