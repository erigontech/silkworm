// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "kv_server.hpp"

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/common/log.hpp>

#include "kv_calls.hpp"

namespace silkworm::db::kv::grpc::server {

using rpc::request_repeatedly;

KvServer::KvServer(
    const rpc::ServerSettings& settings,
    ROAccess chaindata,
    StateChangeCollection* state_change_source)
    : Server(settings),
      chaindata_{std::move(chaindata)},
      state_change_source_{state_change_source} {
    setup_kv_calls();
    SILK_INFO << "KvServer created listening on: " << settings.address_uri;
}

// Register the gRPC services: they must exist for the lifetime of the server built by builder.
void KvServer::register_async_services(::grpc::ServerBuilder& builder) {
    builder.RegisterService(&kv_async_service_);
}

void KvServer::setup_kv_calls() {
    KvVersionCall::fill_predefined_reply();
}

void KvServer::register_kv_request_calls(agrpc::GrpcContext* grpc_context) {
    SILK_TRACE << "KvServer::register_kv_request_calls START";
    auto service = &kv_async_service_;

    // Register one requested call repeatedly for each RPC: asio-grpc will take care of re-registration on any incoming call
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestVersion,
                       [](auto&&... args) -> Task<void> {
                           co_await KvVersionCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestTx,
                       [this, grpc_context](auto&&... args) -> Task<void> {
                           co_await TxCall{*grpc_context, std::forward<decltype(args)>(args)...}(chaindata_);
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestStateChanges,
                       [this](auto&&... args) -> Task<void> {
                           co_await StateChangesCall{std::forward<decltype(args)>(args)...}(state_change_source_);
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestSnapshots,
                       [](auto&&... args) -> Task<void> {
                           co_await SnapshotsCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestGetLatest,
                       [](auto&&... args) -> Task<void> {
                           co_await GetLatestCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestHistorySeek,
                       [](auto&&... args) -> Task<void> {
                           co_await HistorySeekCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestIndexRange,
                       [](auto&&... args) -> Task<void> {
                           co_await IndexRangeCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestHistoryRange,
                       [](auto&&... args) -> Task<void> {
                           co_await HistoryRangeCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestRangeAsOf,
                       [](auto&&... args) -> Task<void> {
                           co_await RangeAsOfCall{std::forward<decltype(args)>(args)...}();
                       });
    SILK_TRACE << "KvServer::register_kv_request_calls END";
}

//! Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void KvServer::register_request_calls() {
    // Start all server-side RPC requests for each available server context
    for (size_t i = 0; i < num_contexts(); ++i) {
        const auto& context = next_context();
        auto grpc_context = context.server_grpc_context();

        // Register initial requested calls for ETHBACKEND and KV services
        register_kv_request_calls(grpc_context);
    }
}

}  // namespace silkworm::db::kv::grpc::server
