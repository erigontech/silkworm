/*
   Copyright 2022 The Silkworm Authors

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

#include "kv_server.hpp"

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/common/log.hpp>

#include "kv_calls.hpp"

namespace silkworm::db::kv::grpc::server {

using rpc::request_repeatedly;

KvServer::KvServer(const rpc::ServerSettings& settings, mdbx::env* chaindata_env, StateChangeCollection* state_change_source)
    : Server(settings), chaindata_env_{chaindata_env}, state_change_source_{state_change_source} {
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
                           co_await TxCall{*grpc_context, std::forward<decltype(args)>(args)...}(chaindata_env_);
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestStateChanges,
                       [this](auto&&... args) -> Task<void> {
                           co_await StateChangesCall{std::forward<decltype(args)>(args)...}(state_change_source_);
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestSnapshots,
                       [](auto&&... args) -> Task<void> {
                           co_await SnapshotsCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestDomainGet,
                       [](auto&&... args) -> Task<void> {
                           co_await DomainGetCall{std::forward<decltype(args)>(args)...}();
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
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestDomainRange,
                       [](auto&&... args) -> Task<void> {
                           co_await DomainRangeCall{std::forward<decltype(args)>(args)...}();
                       });
    SILK_TRACE << "KvServer::register_kv_request_calls END";
}

//! Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void KvServer::register_request_calls() {
    // Start all server-side RPC requests for each available server context
    for (std::size_t i = 0; i < num_contexts(); i++) {
        const auto& context = next_context();
        auto grpc_context = context.server_grpc_context();

        // Register initial requested calls for ETHBACKEND and KV services
        register_kv_request_calls(grpc_context);
    }
}

}  // namespace silkworm::db::kv::grpc::server
