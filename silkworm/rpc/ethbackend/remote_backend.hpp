// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>
#include <vector>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <agrpc/grpc_context.hpp>
#pragma GCC diagnostic pop
#include <evmc/evmc.hpp>

#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/rpc/ethbackend/backend.hpp>
#include <silkworm/rpc/types/execution_payload.hpp>

namespace silkworm::rpc::ethbackend {

class RemoteBackEnd final : public BackEnd {
  public:
    RemoteBackEnd(const std::shared_ptr<grpc::Channel>& channel, agrpc::GrpcContext& grpc_context);
    RemoteBackEnd(std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub, agrpc::GrpcContext& grpc_context);

    Task<evmc::address> etherbase() override;
    Task<uint64_t> protocol_version() override;
    Task<uint64_t> net_version() override;
    Task<std::string> client_version() override;
    Task<uint64_t> net_peer_count() override;
    Task<NodeInfos> engine_node_info() override;
    Task<PeerInfos> peers() override;
    Task<bool> get_block(BlockNum block_num, const HashAsSpan& hash, bool read_senders, silkworm::Block& block) override;
    Task<std::optional<std::pair<BlockNum, TxnId>>> get_block_num_from_txn_hash(const HashAsSpan& hash) override;
    Task<std::optional<BlockNum>> get_block_num_from_hash(const HashAsSpan& hash) override;
    Task<std::optional<evmc::bytes32>> get_block_hash_from_block_num(BlockNum block_num) override;
    Task<std::optional<Bytes>> canonical_body_for_storage(BlockNum block_num) override;

  private:
    static std::vector<Bytes> decode(const ::google::protobuf::RepeatedPtrField<std::string>& grpc_txs);
    static std::vector<Withdrawal> decode(const ::google::protobuf::RepeatedPtrField<::types::Withdrawal>& grpc_withdrawals);

    std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub_;
    agrpc::GrpcContext& grpc_context_;
};

}  // namespace silkworm::rpc::ethbackend
