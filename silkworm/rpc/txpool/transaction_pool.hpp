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

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <agrpc/grpc_context.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <evmc/evmc.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/interfaces/txpool/txpool.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/rpc/common/clock_time.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::txpool {

struct OperationResult {
    bool success;
    std::string error_descr;
};

struct StatusInfo {
    unsigned int queued_count;
    unsigned int pending_count;
    unsigned int base_fee_count;
};

enum TransactionType {
    QUEUED,
    PENDING,
    BASE_FEE
};

struct TransactionInfo {
    TransactionType transaction_type;
    evmc::address sender;
    silkworm::Bytes rlp;
};

using TransactionsInPool = std::vector<TransactionInfo>;

class TransactionPool final {
  public:
    explicit TransactionPool(boost::asio::io_context& context, const std::shared_ptr<grpc::Channel>& channel, agrpc::GrpcContext& grpc_context);

    explicit TransactionPool(boost::asio::io_context::executor_type executor, std::unique_ptr<::txpool::Txpool::StubInterface> stub,
                             agrpc::GrpcContext& grpc_context);

    ~TransactionPool();

    Task<OperationResult> add_transaction(const silkworm::ByteView& rlp_tx);
    Task<std::optional<silkworm::Bytes>> get_transaction(const evmc::bytes32& tx_hash);
    Task<std::optional<uint64_t>> nonce(const evmc::address& address);
    Task<StatusInfo> get_status();
    Task<TransactionsInPool> get_transactions();

  private:
    boost::asio::io_context::executor_type executor_;
    std::unique_ptr<::txpool::Txpool::StubInterface> stub_;
    agrpc::GrpcContext& grpc_context_;
};

}  // namespace silkworm::rpc::txpool
