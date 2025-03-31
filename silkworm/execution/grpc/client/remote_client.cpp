// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "remote_client.hpp"

#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/interfaces/execution/execution.grpc.pb.h>

#include "endpoint/assembly.hpp"
#include "endpoint/checkers.hpp"
#include "endpoint/getters.hpp"
#include "endpoint/insertion.hpp"
#include "endpoint/range.hpp"
#include "endpoint/validation.hpp"

namespace silkworm::execution::grpc::client {

namespace proto = ::execution;
using Stub = proto::Execution::StubInterface;

static std::shared_ptr<::grpc::Channel> make_grpc_channel(const std::string& address_uri) {
    return ::grpc::CreateChannel(address_uri, ::grpc::InsecureChannelCredentials());
}

class RemoteClientImpl final : public api::Service {
  public:
    explicit RemoteClientImpl(const std::string& address_uri, agrpc::GrpcContext& grpc_context)
        : channel_{make_grpc_channel(address_uri)},
          stub_{proto::Execution::NewStub(channel_)},
          grpc_context_{grpc_context} {}

    ~RemoteClientImpl() override = default;

    RemoteClientImpl(const RemoteClientImpl&) = delete;
    RemoteClientImpl& operator=(const RemoteClientImpl&) = delete;

    /** Chain Putters **/

    // rpc InsertBlocks(InsertBlocksRequest) returns(InsertionResult);
    Task<api::InsertionResult> insert_blocks(const api::Blocks& blocks) override {
        auto request = insertion_request_from_blocks(blocks);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncInsertBlocks, *stub_, std::move(request), grpc_context_);
        co_return insertion_result_from_response(reply);
    }

    /** Chain Validation and ForkChoice **/

    // rpc ValidateChain(ValidationRequest) returns(ValidationReceipt);
    Task<api::ValidationResult> validate_chain(BlockId block_id) override {
        auto request = request_from_block_id(block_id);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncValidateChain, *stub_, std::move(request), grpc_context_);
        co_return validation_result_from_response(reply);
    }

    // rpc UpdateForkChoice(ForkChoice) returns(ForkChoiceReceipt);
    Task<api::ForkChoiceResult> update_fork_choice(const api::ForkChoice& fork_choice) override {
        auto request = request_from_fork_choice(fork_choice);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncUpdateForkChoice, *stub_, std::move(request), grpc_context_);
        co_return fork_choice_result_from_response(reply);
    }

    /** Block Assembly **/

    // rpc AssembleBlock(AssembleBlockRequest) returns(AssembleBlockResponse);
    Task<api::AssembleBlockResult> assemble_block(const api::BlockUnderConstruction& block) override {
        auto request = assemble_request_from_block(block);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncAssembleBlock, *stub_, std::move(request), grpc_context_);
        co_return assemble_result_from_response(reply);
    }

    // rpc GetAssembledBlock(GetAssembledBlockRequest) returns(GetAssembledBlockResponse);
    Task<api::AssembledBlockResult> get_assembled_block(api::PayloadId id) override {
        auto request = get_assembled_request_from_payload_id(id);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetAssembledBlock, *stub_, std::move(request), grpc_context_);
        co_return get_assembled_result_from_response(reply);
    }

    /** Chain Getters **/

    // rpc CurrentHeader(google.protobuf.Empty) returns(GetHeaderResponse);
    Task<std::optional<BlockHeader>> current_header() override {
        google::protobuf::Empty request;
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncCurrentHeader, *stub_, std::move(request), grpc_context_);
        co_return header_from_response(reply);
    }

    // rpc GetTD(GetSegmentRequest) returns(GetTDResponse);
    Task<std::optional<TotalDifficulty>> get_td(api::BlockNumOrHash block_num_or_hash) override {
        auto request = request_from_block_num_or_hash(block_num_or_hash);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetTD, *stub_, std::move(request), grpc_context_);
        co_return total_difficulty_from_response(reply);
    }

    // rpc GetHeader(GetSegmentRequest) returns(GetHeaderResponse);
    Task<std::optional<BlockHeader>> get_header(api::BlockNumOrHash block_num_or_hash) override {
        auto request = request_from_block_num_or_hash(block_num_or_hash);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetHeader, *stub_, std::move(request), grpc_context_);
        co_return header_from_response(reply);
    }

    // rpc GetBody(GetSegmentRequest) returns(GetBodyResponse);
    Task<std::optional<BlockBody>> get_body(api::BlockNumOrHash block_num_or_hash) override {
        auto request = request_from_block_num_or_hash(block_num_or_hash);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetBody, *stub_, std::move(request), grpc_context_);
        co_return body_from_response(reply);
    }

    // rpc HasBlock(GetSegmentRequest) returns(HasBlockResponse);
    Task<bool> has_block(api::BlockNumOrHash block_num_or_hash) override {
        auto request = request_from_block_num_or_hash(block_num_or_hash);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncHasBlock, *stub_, std::move(request), grpc_context_);
        co_return reply.has_block();
    }

    /** Ranges **/

    // rpc GetBodiesByRange(GetBodiesByRangeRequest) returns(GetBodiesBatchResponse);
    Task<api::BlockBodies> get_bodies_by_range(BlockNumRange range) override {
        auto request = bodies_request_from_block_num_range(range);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetBodiesByRange, *stub_, std::move(request), grpc_context_);
        co_return block_bodies_from_response(reply);
    }

    // rpc GetBodiesByHashes(GetBodiesByHashesRequest) returns(GetBodiesBatchResponse);
    Task<api::BlockBodies> get_bodies_by_hashes(const api::BlockHashes& hashes) override {
        auto request = bodies_request_from_block_hashes(hashes);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetBodiesByHashes, *stub_, std::move(request), grpc_context_);
        co_return block_bodies_from_response(reply);
    }

    /** Chain Checkers **/

    // rpc IsCanonicalHash(types.H256) returns(IsCanonicalResponse);
    Task<bool> is_canonical_hash(Hash block_hash) override {
        auto request = h256_from_block_hash(block_hash);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncIsCanonicalHash, *stub_, std::move(request), grpc_context_);
        co_return reply.canonical();
    }

    // rpc GetHeaderHashNumber(types.H256) returns(GetHeaderHashNumberResponse);
    Task<std::optional<BlockNum>> get_header_hash_number(Hash block_hash) override {
        auto request = h256_from_block_hash(block_hash);
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetHeaderHashNumber, *stub_, std::move(request), grpc_context_);
        co_return block_num_from_response(reply);
    }

    // rpc GetForkChoice(google.protobuf.Empty) returns(ForkChoice);
    Task<api::ForkChoice> get_fork_choice() override {
        google::protobuf::Empty request;
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetForkChoice, *stub_, std::move(request), grpc_context_);
        co_return fork_choice_from_response(reply);
    }

    /** Misc **/

    // rpc Ready(google.protobuf.Empty) returns(ReadyResponse);
    Task<bool> ready() override {
        google::protobuf::Empty request;
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncReady, *stub_, std::move(request), grpc_context_);
        co_return reply.ready();
    }

    // rpc FrozenBlocks(google.protobuf.Empty) returns(FrozenBlocksResponse);
    Task<uint64_t> frozen_blocks() override {
        google::protobuf::Empty request;
        const auto reply = co_await rpc::unary_rpc(&Stub::AsyncFrozenBlocks, *stub_, std::move(request), grpc_context_);
        co_return reply.frozen_blocks();
    }

    /** Additional non-RPC methods **/

    Task<api::BlockHeaders> get_last_headers(uint64_t n) override {
        api::BlockHeaders last_headers;
        if (n == 0) {
            co_return last_headers;
        }
        last_headers.reserve(n);
        auto last_finalized_header{co_await current_header()};
        if (!last_finalized_header) {
            co_return last_headers;
        }
        BlockNum last_block_num = last_finalized_header->number;
        last_headers.push_back(std::move(*last_finalized_header));
        for (BlockNum block_num = last_block_num - 1; block_num < last_block_num - n; --block_num) {
            auto header{co_await get_header(block_num)};
            if (header) {
                last_headers.push_back(std::move(*header));
            }
        }
        co_return last_headers;
    }

    Task<BlockNum> block_progress() override {
        // This should return the last header inserted into the database but such RPC does not exist
        // TODO(canepat) we should either add RPC or get rid of this by refactoring sync
        const auto last_finalized_header{co_await current_header()};
        co_return last_finalized_header->number;
    }

  private:
    std::shared_ptr<::grpc::Channel> channel_;
    std::unique_ptr<Stub> stub_;
    agrpc::GrpcContext& grpc_context_;
};

RemoteClient::RemoteClient(const std::string& address_uri, agrpc::GrpcContext& grpc_context)
    : p_impl_(std::make_shared<RemoteClientImpl>(address_uri, grpc_context)) {}

// Must be here (not in header) because RemoteClientImpl size is necessary for std::unique_ptr in PIMPL idiom
RemoteClient::~RemoteClient() = default;

std::shared_ptr<api::Service> RemoteClient::service() {
    return p_impl_;
}

}  // namespace silkworm::execution::grpc::client
