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

#include "remote_transaction.hpp"

#include <silkworm/db/state/remote_state.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/common/errors.hpp>

#include "endpoint/temporal_range.hpp"

namespace silkworm::db::kv::grpc::client {

namespace proto = ::remote;
using Stub = proto::KV::StubInterface;

RemoteTransaction::RemoteTransaction(
    Stub& stub,
    agrpc::GrpcContext& grpc_context,
    api::StateCache* state_cache,
    chain::BlockProvider block_provider,
    chain::BlockNumberFromTxnHashProvider block_number_from_txn_hash_provider)
    : BaseTransaction(state_cache),
      block_provider_{std::move(block_provider)},
      block_number_from_txn_hash_provider_{std::move(block_number_from_txn_hash_provider)},
      stub_{stub},
      grpc_context_{grpc_context},
      tx_rpc_{stub_, grpc_context_} {}

Task<void> RemoteTransaction::open() {
    const auto tx_result = co_await tx_rpc_.request_and_read();
    tx_id_ = tx_result.tx_id();
    view_id_ = tx_result.view_id();
}

Task<std::shared_ptr<api::Cursor>> RemoteTransaction::cursor(const std::string& table) {
    co_return co_await get_cursor(table, false);
}

Task<std::shared_ptr<api::CursorDupSort>> RemoteTransaction::cursor_dup_sort(const std::string& table) {
    co_return co_await get_cursor(table, true);
}

Task<void> RemoteTransaction::close() {
    co_await tx_rpc_.writes_done_and_finish();
    cursors_.clear();
    tx_id_ = 0;
    view_id_ = 0;
}

Task<std::shared_ptr<api::CursorDupSort>> RemoteTransaction::get_cursor(const std::string& table, bool is_cursor_dup_sort) {
    if (is_cursor_dup_sort) {
        const auto cursor_it = dup_cursors_.find(table);
        if (cursor_it != dup_cursors_.end()) {
            co_return cursor_it->second;
        }
    } else {
        const auto cursor_it = cursors_.find(table);
        if (cursor_it != cursors_.end()) {
            co_return cursor_it->second;
        }
    }
    auto cursor = std::make_shared<RemoteCursor>(tx_rpc_);
    co_await cursor->open_cursor(table, is_cursor_dup_sort);
    if (is_cursor_dup_sort) {
        dup_cursors_[table] = cursor;
    } else {
        cursors_[table] = cursor;
    }
    co_return cursor;
}

std::shared_ptr<silkworm::State> RemoteTransaction::create_state(boost::asio::any_io_executor& executor, const chain::ChainStorage& storage, BlockNum block_number) {
    return std::make_shared<db::state::RemoteState>(executor, *this, storage, block_number);
}

std::shared_ptr<chain::ChainStorage> RemoteTransaction::create_storage() {
    return std::make_shared<chain::RemoteChainStorage>(*this, block_provider_, block_number_from_txn_hash_provider_);
}

Task<api::PaginatedTimestamps> RemoteTransaction::index_range(api::IndexRangeQuery&& query) {
    auto paginator = [&, query = std::move(query)]() mutable -> Task<api::PaginatedTimestamps::PageResult> {
        static std::string page_token{query.page_token};
        query.tx_id = tx_id_;
        query.page_token = page_token;
        auto request = index_range_request_from_query(query);
        try {
            auto reply = co_await rpc::unary_rpc(&Stub::AsyncIndexRange, stub_, std::move(request), grpc_context_);
            auto result = index_range_result_from_response(reply);
            page_token = std::move(result.next_page_token);
            co_return api::PaginatedTimestamps::PageResult{std::move(result.timestamps), !page_token.empty()};
        } catch (rpc::GrpcStatusError& gse) {
            SILK_WARN << "KV::IndexRange RPC failed status=" << gse.status();
            throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
        }
    };
    co_return api::PaginatedTimestamps{std::move(paginator)};
}

Task<api::PaginatedKeysValues> RemoteTransaction::history_range(api::HistoryRangeQuery&& query) {
    auto paginator = [&, query = std::move(query)]() mutable -> Task<api::PaginatedKeysValues::PageResult> {
        static std::string page_token{query.page_token};
        query.tx_id = tx_id_;
        query.page_token = page_token;
        auto request = history_range_request_from_query(query);
        try {
            auto reply = co_await rpc::unary_rpc(&Stub::AsyncHistoryRange, stub_, std::move(request), grpc_context_);
            auto result = history_range_result_from_response(reply);
            page_token = std::move(result.next_page_token);
            co_return api::PaginatedKeysValues::PageResult{std::move(result.keys), std::move(result.values), !page_token.empty()};
        } catch (rpc::GrpcStatusError& gse) {
            SILK_WARN << "KV::HistoryRange RPC failed status=" << gse.status();
            throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
        }
    };
    co_return api::PaginatedKeysValues{std::move(paginator)};
}

Task<api::PaginatedKeysValues> RemoteTransaction::domain_range(api::DomainRangeQuery&& query) {
    auto paginator = [&, query = std::move(query)]() mutable -> Task<api::PaginatedKeysValues::PageResult> {
        static std::string page_token{query.page_token};
        query.tx_id = tx_id_;
        query.page_token = page_token;
        auto request = domain_range_request_from_query(query);
        try {
            auto reply = co_await rpc::unary_rpc(&Stub::AsyncDomainRange, stub_, std::move(request), grpc_context_);
            auto result = history_range_result_from_response(reply);
            page_token = std::move(result.next_page_token);
            co_return api::PaginatedKeysValues::PageResult{std::move(result.keys), std::move(result.values), !page_token.empty()};
        } catch (rpc::GrpcStatusError& gse) {
            SILK_WARN << "KV::DomainRange RPC failed status=" << gse.status();
            throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
        }
    };
    co_return api::PaginatedKeysValues{std::move(paginator)};
}

}  // namespace silkworm::db::kv::grpc::client
