/*
   Copyright 2024 The Silkworm Authors

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

#include "remote_client.hpp"

#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/call.hpp>

#include "endpoint/temporal_point.hpp"
#include "endpoint/temporal_range.hpp"

namespace silkworm::kv::grpc::client {

namespace proto = ::remote;
using Stub = proto::KV::StubInterface;

static std::shared_ptr<::grpc::Channel> make_grpc_channel(const std::string& address_uri) {
    return ::grpc::CreateChannel(address_uri, ::grpc::InsecureChannelCredentials());
}

class RemoteClientImpl final : public api::Service {
  public:
    explicit RemoteClientImpl(const std::string& address_uri, agrpc::GrpcContext& grpc_context)
        : channel_{make_grpc_channel(address_uri)},
          stub_{proto::KV::NewStub(channel_)},
          grpc_context_{grpc_context} {}
    explicit RemoteClientImpl(std::unique_ptr<Stub> stub, agrpc::GrpcContext& grpc_context)
        : stub_{std::move(stub)},
          grpc_context_{grpc_context} {}

    ~RemoteClientImpl() override = default;

    RemoteClientImpl(const RemoteClientImpl&) = delete;
    RemoteClientImpl& operator=(const RemoteClientImpl&) = delete;

    // rpc Version(google.protobuf.Empty) returns (types.VersionReply);
    Task<api::Version> version() override {
        co_return api::kCurrentVersion;
    }

    // rpc Tx(stream Cursor) returns (stream Pair);
    Task<std::unique_ptr<db::kv::api::Transaction>> begin_transaction() override {
        // TODO(canepat) implement
        co_return nullptr;
    }

    /** Temporal Point Queries **/

    // rpc HistoryGet(HistoryGetReq) returns (HistoryGetReply);
    Task<api::HistoryPointResult> get_history(const api::HistoryPointQuery& query) override {
        auto request = history_get_request_from_query(query);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncHistoryGet, stub_, std::move(request), grpc_context_);
        co_return history_get_result_from_response(reply);
    }

    // rpc DomainGet(DomainGetReq) returns (DomainGetReply);
    Task<api::DomainPointResult> get_domain(const api::DomainPointQuery& query) override {
        auto request = domain_get_request_from_query(query);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncDomainGet, stub_, std::move(request), grpc_context_);
        co_return domain_get_result_from_response(reply);
    }

    /** Temporal Range Queries **/

    // rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
    Task<api::IndexRangeResult> get_index_range(const api::IndexRangeQuery& query) override {
        auto request = index_range_request_from_query(query);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncIndexRange, stub_, std::move(request), grpc_context_);
        co_return index_range_result_from_response(reply);
    }

    // rpc HistoryRange(HistoryRangeReq) returns (Pairs);
    Task<api::HistoryRangeResult> get_history_range(const api::HistoryRangeQuery& query) override {
        auto request = history_range_request_from_query(query);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncHistoryRange, stub_, std::move(request), grpc_context_);
        co_return history_range_result_from_response(reply);
    }

    // rpc DomainRange(DomainRangeReq) returns (Pairs);
    Task<api::DomainRangeResult> get_domain_range(const api::DomainRangeQuery& query) override {
        auto request = domain_range_request_from_query(query);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncDomainRange, stub_, std::move(request), grpc_context_);
        co_return domain_range_result_from_response(reply);
    }

  private:
    std::shared_ptr<::grpc::Channel> channel_;
    std::unique_ptr<Stub> stub_;
    agrpc::GrpcContext& grpc_context_;
};

RemoteClient::RemoteClient(const std::string& address_uri, agrpc::GrpcContext& grpc_context)
    : p_impl_{std::make_shared<RemoteClientImpl>(address_uri, grpc_context)} {}

RemoteClient::RemoteClient(std::unique_ptr<Stub> stub, agrpc::GrpcContext& grpc_context)
    : p_impl_{std::make_shared<RemoteClientImpl>(std::move(stub), grpc_context)} {}

// Must be here (not in header) because RemoteClientImpl size is necessary for std::unique_ptr in PIMPL idiom
RemoteClient::~RemoteClient() = default;

std::shared_ptr<api::Service> RemoteClient::service() {
    return p_impl_;
}

}  // namespace silkworm::kv::grpc::client
