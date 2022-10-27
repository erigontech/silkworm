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

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <tuple>
#include <unordered_set>

#include <silkworm/concurrency/coroutine.hpp>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/awaitable.hpp>
#include <evmc/evmc.hpp>
#include <grpcpp/grpcpp.h>
#include <gsl/pointers>
#include <intx/intx.hpp>
#include <p2psentry/sentry.grpc.pb.h>
#include <types/types.pb.h>

#include <silkworm/backend/ethereum_backend.hpp>
#include <silkworm/common/assert.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rpc/client/call.hpp>

namespace silkworm::rpc {

struct SentryStatus {
    uint64_t network_id;
    evmc::bytes32 head_hash;
    intx::uint256 head_td;
    evmc::bytes32 genesis_hash;
    std::vector<BlockNum> forks;
};

class SentryClient {
  public:
    using SetStatusResult = std::pair<grpc::Status, sentry::SetStatusReply>;
    using PeerCountResult = std::pair<grpc::Status, sentry::PeerCountReply>;
    using NodeInfoResult = std::pair<grpc::Status, types::NodeInfoReply>;

    virtual ~SentryClient() = default;

    virtual boost::asio::awaitable<SetStatusResult> set_status(SentryStatus sentry_status) = 0;
    virtual boost::asio::awaitable<PeerCountResult> peer_count() = 0;
    virtual boost::asio::awaitable<NodeInfoResult> node_info() = 0;
};

class SentryClientFactory {
  public:
    virtual ~SentryClientFactory() = default;

    virtual std::unique_ptr<SentryClient> make_sentry_client(const std::string& address_uri) = 0;
};

class RemoteSentryClient : public SentryClient {
  public:
    RemoteSentryClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel,
                       std::string address_uri);

    RemoteSentryClient(const RemoteSentryClient&) = delete;
    RemoteSentryClient& operator=(const RemoteSentryClient&) = delete;

    boost::asio::awaitable<SetStatusResult> set_status(SentryStatus sentry_status) override;
    boost::asio::awaitable<PeerCountResult> peer_count() override;
    boost::asio::awaitable<NodeInfoResult> node_info() override;

  private:
    agrpc::GrpcContext& grpc_context_;
    std::unique_ptr<sentry::Sentry::Stub> stub_;
    std::string address_uri_;
};

class RemoteSentryClientFactory : public SentryClientFactory {
  public:
    explicit RemoteSentryClientFactory(agrpc::GrpcContext& grpc_context) : grpc_context_(grpc_context) {}

    std::unique_ptr<SentryClient> make_sentry_client(const std::string& address_uri) override;

  private:
    agrpc::GrpcContext& grpc_context_;
};

}  // namespace silkworm::rpc
