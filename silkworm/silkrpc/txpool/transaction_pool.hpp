/*
    Copyright 2020-2021 The Silkrpc Authors

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

#include <silkworm/silkrpc/config.hpp>

#include <agrpc/grpc_context.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <evmc/evmc.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/silkrpc/common/clock_time.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/interfaces/txpool/txpool.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/core/common/base.hpp>

namespace silkrpc::txpool {

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
    explicit TransactionPool(boost::asio::io_context& context, std::shared_ptr<grpc::Channel> channel, agrpc::GrpcContext& grpc_context);

    explicit TransactionPool(boost::asio::io_context::executor_type executor, std::unique_ptr<::txpool::Txpool::StubInterface> stub,
        agrpc::GrpcContext& grpc_context);

    ~TransactionPool();

    boost::asio::awaitable<OperationResult> add_transaction(const silkworm::ByteView& rlp_tx);

    boost::asio::awaitable<std::optional<silkworm::Bytes>> get_transaction(const evmc::bytes32& tx_hash);

    boost::asio::awaitable<std::optional<uint64_t>> nonce(const evmc::address& address);

    boost::asio::awaitable<StatusInfo> get_status();

    boost::asio::awaitable<TransactionsInPool> get_transactions();

private:
    evmc::address address_from_H160(const types::H160& h160);
    types::H160* H160_from_address(const evmc::address& address);
    types::H128* H128_from_bytes(const uint8_t* bytes);

    boost::asio::io_context::executor_type executor_;
    std::unique_ptr<::txpool::Txpool::StubInterface> stub_;
    agrpc::GrpcContext& grpc_context_;
};

} // namespace silkrpc::txpool

