// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <silkworm/infra/concurrency/task.hpp>

#include <grpcpp/grpcpp.h>
#include <gsl/util>

#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/grpc/server/call.hpp>
#include <silkworm/interfaces/execution/execution.grpc.pb.h>

#include "../../api/direct_service.hpp"

namespace silkworm::execution::grpc::server {

namespace protobuf = google::protobuf;
namespace proto = ::execution;
namespace proto_types = ::types;
using AsyncService = proto::Execution::AsyncService;

// rpc InsertBlocks(InsertBlocksRequest) returns(InsertionResult);
class InsertBlocksCall : public rpc::server::UnaryCall<proto::InsertBlocksRequest, proto::InsertionResult> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc ValidateChain(ValidationRequest) returns(ValidationReceipt);
class ValidateChainCall : public rpc::server::UnaryCall<proto::ValidationRequest, proto::ValidationReceipt> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc UpdateForkChoice(ForkChoice) returns(ForkChoiceReceipt);
class UpdateForkChoiceCall : public rpc::server::UnaryCall<proto::ForkChoice, proto::ForkChoiceReceipt> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc AssembleBlock(AssembleBlockRequest) returns(AssembleBlockResponse);
class AssembleBlockCall : public rpc::server::UnaryCall<proto::AssembleBlockRequest, proto::AssembleBlockResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc GetAssembledBlock(GetAssembledBlockRequest) returns(GetAssembledBlockResponse);
class GetAssembledBlockCall : public rpc::server::UnaryCall<proto::GetAssembledBlockRequest, proto::GetAssembledBlockResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc CurrentHeader(google.protobuf.Empty) returns(GetHeaderResponse);
class CurrentHeaderCall : public rpc::server::UnaryCall<protobuf::Empty, proto::GetHeaderResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc GetTD(GetSegmentRequest) returns(GetTDResponse);
class GetTDCall : public rpc::server::UnaryCall<proto::GetSegmentRequest, proto::GetTDResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc GetHeader(GetSegmentRequest) returns(GetHeaderResponse);
class GetHeaderCall : public rpc::server::UnaryCall<proto::GetSegmentRequest, proto::GetHeaderResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc GetBody(GetSegmentRequest) returns(GetBodyResponse);
class GetBodyCall : public rpc::server::UnaryCall<proto::GetSegmentRequest, proto::GetBodyResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc HasBlock(GetSegmentRequest) returns(HasBlockResponse);
class HasBlockCall : public rpc::server::UnaryCall<proto::GetSegmentRequest, proto::HasBlockResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc GetBodiesByRange(GetBodiesByRangeRequest) returns(GetBodiesBatchResponse);
class GetBodiesByRangeCall : public rpc::server::UnaryCall<proto::GetBodiesByRangeRequest, proto::GetBodiesBatchResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc GetBodiesByHashes(GetBodiesByHashesRequest) returns(GetBodiesBatchResponse);
class GetBodiesByHashesCall : public rpc::server::UnaryCall<proto::GetBodiesByHashesRequest, proto::GetBodiesBatchResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc IsCanonicalHash(types.H256) returns(IsCanonicalResponse);
class IsCanonicalHashCall : public rpc::server::UnaryCall<proto_types::H256, proto::IsCanonicalResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc GetHeaderHashNumber(types.H256) returns(GetHeaderHashNumberResponse);
class GetHeaderHashNumberCall : public rpc::server::UnaryCall<proto_types::H256, proto::GetHeaderHashNumberResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc GetForkChoice(google.protobuf.Empty) returns(ForkChoice);
class GetForkChoiceCall : public rpc::server::UnaryCall<protobuf::Empty, proto::ForkChoice> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc Ready(google.protobuf.Empty) returns(ReadyResponse);
class ReadyCall : public rpc::server::UnaryCall<protobuf::Empty, proto::ReadyResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

// rpc FrozenBlocks(google.protobuf.Empty) returns(FrozenBlocksResponse);
class FrozenBlocksCall : public rpc::server::UnaryCall<protobuf::Empty, proto::FrozenBlocksResponse> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(api::DirectService& service);
};

}  // namespace silkworm::execution::grpc::server
