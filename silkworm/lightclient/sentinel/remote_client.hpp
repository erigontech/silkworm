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

#include <memory>

#include <silkworm/node/concurrency/coroutine.hpp>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/awaitable.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/interfaces/p2psentinel/sentinel.grpc.pb.h>
#include <silkworm/lightclient/sentinel/sentinel_client.hpp>

namespace silkworm::cl::sentinel {

class RemoteClient : public Client {
  public:
    RemoteClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel);

    boost::asio::awaitable<void> start() override;

    boost::asio::awaitable<std::shared_ptr<eth::LightClientBootstrap>> bootstrap_request_v1(const eth::Root& root) override;

  private:
    agrpc::GrpcContext& grpc_context_;
    std::unique_ptr<::sentinel::Sentinel::Stub> stub_;
};

}  // namespace silkworm::cl::sentinel
