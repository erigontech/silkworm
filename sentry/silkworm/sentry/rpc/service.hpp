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

#include <silkworm/concurrency/coroutine.hpp>

#include <agrpc/grpc_context.hpp>
#include <p2psentry/sentry.grpc.pb.h>

#include <silkworm/sentry/common/channel.hpp>
#include <silkworm/sentry/eth/status_data.hpp>

namespace silkworm::sentry::rpc {

class ServiceImpl;

struct ServiceState {
    uint8_t eth_version;
    common::Channel<eth::StatusData>& status_channel;
};

class Service final {
  public:
    explicit Service(ServiceState state);
    ~Service();

    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;

    void register_request_calls(
        agrpc::GrpcContext* grpc_context,
        ::sentry::Sentry::AsyncService* async_service);

  private:
    std::unique_ptr<ServiceImpl> p_impl_;
};

}  // namespace silkworm::sentry::rpc
