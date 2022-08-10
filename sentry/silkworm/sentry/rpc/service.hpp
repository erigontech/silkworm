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

#include <boost/asio/io_context.hpp>
#include <grpcpp/grpcpp.h>
#include <p2psentry/sentry.grpc.pb.h>

namespace silkworm::sentry::rpc {

class ServiceImpl;

class Service final {
  public:
    Service();
    ~Service();

    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;

    void register_request_calls(
        boost::asio::io_context& scheduler,
        ::sentry::Sentry::AsyncService* async_service,
        grpc::ServerCompletionQueue* queue);

  private:
    std::unique_ptr<ServiceImpl> p_impl_;
};

}  // namespace silkworm::sentry::rpc
