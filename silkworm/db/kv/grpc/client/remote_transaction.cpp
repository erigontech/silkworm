// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "remote_transaction.hpp"

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/txn_num.hpp>
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

std::shared_ptr<chain::ChainStorage> RemoteTransaction::make_storage() {
    return std::make_shared<chain::RemoteChainStorage>(*this, providers_);
}

Task<TxnId> RemoteTransaction::first_txn_num_in_block(BlockNum block_num) {
    const auto min_txn_num = co_await txn::min_tx_num(*this, block_num, providers_.canonical_body_for_storage);
    co_return min_txn_num + /*txn_index*/ 0;
}

Task<api::GetLatestResult> RemoteTransaction::get_latest(api::GetLatestRequest request) {
    try {
        request.tx_id = tx_id_;
        auto req = make_get_latest_req(request);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetLatest, stub_, std::move(req), grpc_context_);
        auto result = get_latest_result_from_response(reply);
        co_return result;
    } catch (rpc::GrpcStatusError& gse) {
        SILK_WARN << "KV::GetLatest (latest) RPC failed status=" << gse.status();
        throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
    }
}

Task<api::GetAsOfResult> RemoteTransaction::get_as_of(api::GetAsOfRequest request) {
    try {
        request.tx_id = tx_id_;
        auto req = make_get_as_of_req(request);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetLatest, stub_, std::move(req), grpc_context_);
        auto result = get_as_of_result_from_response(reply);
        co_return result;
    } catch (rpc::GrpcStatusError& gse) {
        SILK_WARN << "KV::GetLatest (as_of) RPC failed status=" << gse.status();
        throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
    }
}

Task<api::HistoryPointResult> RemoteTransaction::history_seek(api::HistoryPointRequest request) {
    try {
        request.tx_id = tx_id_;
        auto req = make_history_seek_req(request);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncHistorySeek, stub_, std::move(req), grpc_context_);
        auto result = history_seek_result_from_response(reply);
        co_return result;
    } catch (rpc::GrpcStatusError& gse) {
        SILK_WARN << "KV::HistorySeek RPC failed status=" << gse.status();
        throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
    }
}

Task<api::PaginatedTimestamps> RemoteTransaction::index_range(api::IndexRangeRequest request) {
    auto paginator = [&, request = std::move(request)](api::PaginatedTimestamps::PageToken page_token) mutable -> Task<api::PaginatedTimestamps::PageResult> {
        request.tx_id = tx_id_;
        request.page_token = std::move(page_token);
        auto req = make_index_range_req(request);
        try {
            const auto reply = co_await rpc::unary_rpc(&Stub::AsyncIndexRange, stub_, std::move(req), grpc_context_);
            auto result = index_range_result_from_response(reply);

            co_return api::PaginatedTimestamps::PageResult{std::move(result.timestamps), std::move(result.next_page_token)};
        } catch (rpc::GrpcStatusError& gse) {
            SILK_WARN << "KV::IndexRange RPC failed status=" << gse.status();
            throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
        }
    };
    co_return api::PaginatedTimestamps{std::move(paginator)};
}

Task<api::PaginatedKeysValues> RemoteTransaction::history_range(api::HistoryRangeRequest request) {
    auto paginator = [&, request = std::move(request)](api::PaginatedKeysValues::PageToken page_token) mutable -> Task<api::PaginatedKeysValues::PageResult> {
        request.tx_id = tx_id_;
        request.page_token = std::move(page_token);
        auto req = make_history_range_req(request);
        try {
            const auto reply = co_await rpc::unary_rpc(&Stub::AsyncHistoryRange, stub_, std::move(req), grpc_context_);
            auto result = history_range_result_from_response(reply);

            co_return api::PaginatedKeysValues::PageResult{std::move(result.keys), std::move(result.values), std::move(result.next_page_token)};
        } catch (rpc::GrpcStatusError& gse) {
            SILK_WARN << "KV::HistoryRange RPC failed status=" << gse.status();
            throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
        }
    };
    co_return api::PaginatedKeysValues{std::move(paginator)};
}

Task<api::PaginatedKeysValues> RemoteTransaction::range_as_of(api::DomainRangeRequest request) {
    auto paginator = [&, request = std::move(request)](api::PaginatedKeysValues::PageToken page_token) mutable -> Task<api::PaginatedKeysValues::PageResult> {
        request.tx_id = tx_id_;
        request.page_token = std::move(page_token);
        auto req = make_domain_range_req(request);
        try {
            const auto reply = co_await rpc::unary_rpc(&Stub::AsyncRangeAsOf, stub_, std::move(req), grpc_context_);
            auto result = history_range_result_from_response(reply);

            co_return api::PaginatedKeysValues::PageResult{std::move(result.keys), std::move(result.values), std::move(result.next_page_token)};
        } catch (rpc::GrpcStatusError& gse) {
            SILK_WARN << "KV::RangeAsOf RPC failed status=" << gse.status();
            throw boost::system::system_error{rpc::to_system_code(gse.status().error_code())};
        }
    };
    co_return api::PaginatedKeysValues{std::move(paginator)};
}

}  // namespace silkworm::db::kv::grpc::client
