// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <agrpc/grpc_context.hpp>
#pragma GCC diagnostic pop
#include <evmc/evmc.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/interfaces/txpool/txpool.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::txpool {

struct OperationResult {
    bool success{false};
    std::string error_descr;
};

struct StatusInfo {
    unsigned int queued_count{0};
    unsigned int pending_count{0};
    unsigned int base_fee_count{0};
};

enum TransactionType {
    kQueued,
    kPending,
    kBaseFee
};

struct TransactionInfo {
    TransactionType transaction_type;
    evmc::address sender;
    silkworm::Bytes rlp;
};

using TransactionsInPool = std::vector<TransactionInfo>;

class TransactionPool final {
  public:
    TransactionPool(const std::shared_ptr<grpc::Channel>& channel, agrpc::GrpcContext& grpc_context);
    TransactionPool(std::unique_ptr<::txpool::Txpool::StubInterface> stub, agrpc::GrpcContext& grpc_context);

    Task<OperationResult> add_transaction(const silkworm::ByteView& rlp_tx);
    Task<std::optional<silkworm::Bytes>> get_transaction(const evmc::bytes32& tx_hash);
    Task<std::optional<uint64_t>> nonce(const evmc::address& address);
    Task<StatusInfo> get_status();
    Task<TransactionsInPool> get_transactions();

  private:
    std::unique_ptr<::txpool::Txpool::StubInterface> stub_;
    agrpc::GrpcContext& grpc_context_;
};

}  // namespace silkworm::rpc::txpool
