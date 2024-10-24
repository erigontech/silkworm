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

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/state/remote_state.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/common/errors.hpp>
#include <silkworm/infra/grpc/common/util.hpp>

#include "endpoint/temporal_point.hpp"
#include "endpoint/temporal_range.hpp"

namespace silkworm::db::kv::grpc::client {

namespace proto = ::remote;
using Stub = proto::KV::StubInterface;

RemoteTransaction::RemoteTransaction(
    Stub& stub,
    agrpc::GrpcContext& grpc_context,
    api::StateCache* state_cache,
    chain::Providers providers)
    : BaseTransaction(state_cache),
      providers_{std::move(providers)},
      stub_{stub},
      grpc_context_{grpc_context},
      tx_rpc_{grpc_context_} {}

Task<void> RemoteTransaction::open() {
    start_called_ = true;
    if (!co_await tx_rpc_.start(stub_)) {
        const ::grpc::Status status = co_await tx_rpc_.finish();
        SILK_TRACE << "Tx RPC start failed status=" << status;
        throw boost::system::system_error{rpc::to_system_code(status.error_code())};
    }
    TxRpc::Response tx_id_view_id_pair{};
    if (!co_await tx_rpc_.read(tx_id_view_id_pair)) {
        const ::grpc::Status status = co_await tx_rpc_.finish();
        SILK_TRACE << "Tx RPC initial read failed status=" << status;
        throw boost::system::system_error{rpc::to_system_code(status.error_code())};
    }
    tx_id_ = tx_id_view_id_pair.tx_id();
    view_id_ = tx_id_view_id_pair.view_id();
}

Task<std::shared_ptr<api::Cursor>> RemoteTransaction::cursor(const std::string& table) {
    if (!start_called_) {
        throw boost::system::system_error{rpc::to_system_code(::grpc::StatusCode::INTERNAL)};
    }
    co_return co_await get_cursor(table, false);
}

Task<std::shared_ptr<api::CursorDupSort>> RemoteTransaction::cursor_dup_sort(const std::string& table) {
    if (!start_called_) {
        throw boost::system::system_error{rpc::to_system_code(::grpc::StatusCode::INTERNAL)};
    }
    co_return co_await get_cursor(table, true);
}

Task<void> RemoteTransaction::close() {
    if (!start_called_) {
        throw boost::system::system_error{rpc::to_system_code(::grpc::StatusCode::INTERNAL)};
    }
    ::grpc::Status status = co_await tx_rpc_.finish();
    if (!status.ok()) {
        SILK_TRACE << "Tx RPC finish failed status=" << status;
        throw boost::system::system_error{rpc::to_system_code(status.error_code())};
    }
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
    return std::make_shared<db::state::RemoteState>(executor, *this, storage, block_number, providers_);
}

std::shared_ptr<chain::ChainStorage> RemoteTransaction::create_storage() {
    return std::make_shared<chain::RemoteChainStorage>(*this, providers_);
}

Task<api::DomainPointResult> RemoteTransaction::domain_get(api::DomainPointQuery&& query) {  // NOLINT(*-rvalue-reference-param-not-moved)
    try {
        query.tx_id = tx_id_;
        auto request = domain_get_request_from_query(query);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncDomainGet, stub_, std::move(request), grpc_context_);
        auto result = domain_get_result_from_response(reply);
        co_return result;
    } catch (rpc::GrpcStatusError& gse) {
        SILK_WARN << "KV::DomainGet RPC failed status=" << gse.status();
        throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
    }
}

Task<api::HistoryPointResult> RemoteTransaction::history_seek(api::HistoryPointQuery&& query) {  // NOLINT(*-rvalue-reference-param-not-moved)
    try {
        query.tx_id = tx_id_;
        auto request = history_seek_request_from_query(query);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncHistorySeek, stub_, std::move(request), grpc_context_);
        auto result = history_seek_result_from_response(reply);
        co_return result;
    } catch (rpc::GrpcStatusError& gse) {
        SILK_WARN << "KV::HistorySeek RPC failed status=" << gse.status();
        throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
    }
}

Task<api::PaginatedTimestamps> RemoteTransaction::index_range(api::IndexRangeQuery&& query) {
    auto paginator = [&, query = std::move(query)]() mutable -> Task<api::PaginatedTimestamps::PageResult> {
        static std::string page_token{query.page_token};
        query.tx_id = tx_id_;
        query.page_token = page_token;
        auto request = index_range_request_from_query(query);
        try {
            const auto reply = co_await rpc::unary_rpc(&Stub::AsyncIndexRange, stub_, std::move(request), grpc_context_);
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
            const auto reply = co_await rpc::unary_rpc(&Stub::AsyncHistoryRange, stub_, std::move(request), grpc_context_);
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
            const auto reply = co_await rpc::unary_rpc(&Stub::AsyncDomainRange, stub_, std::move(request), grpc_context_);
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
