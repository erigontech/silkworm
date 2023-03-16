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

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <silkworm/node/concurrency/coroutine.hpp>

#include <agrpc/detail/forward.hpp>
#include <boost/asio/awaitable.hpp>

#include <silkworm/sentry/api/api_common/service.hpp>

namespace silkworm::sentry::rpc::client {

// TODO: move to a common place for all clients
struct ISentryClient {
    virtual ~ISentryClient() = 0;

    virtual boost::asio::awaitable<void> service(std::function<boost::asio::awaitable<void>(api::api_common::Service&)> consumer) = 0;

    template <typename TResult>
    boost::asio::awaitable<TResult> service(std::function<boost::asio::awaitable<TResult>(api::api_common::Service&)> consumer) {
        std::optional<TResult> result;
        co_await service([consumer = std::move(consumer), &result](api::api_common::Service& service) -> boost::asio::awaitable<void> {
            *result = co_await consumer(service);
        });
        co_return std::move(*result);
    }
};

class SentryClientImpl;

class SentryClient : public ISentryClient {
  public:
    explicit SentryClient(const std::string& address_uri, agrpc::GrpcContext& grpc_context);
    ~SentryClient() override;

    SentryClient(const SentryClient&) = delete;
    SentryClient& operator=(const SentryClient&) = delete;

    boost::asio::awaitable<void> service(std::function<boost::asio::awaitable<void>(api::api_common::Service&)> consumer) override;

  private:
    std::unique_ptr<SentryClientImpl> p_impl_;
};

}  // namespace silkworm::sentry::rpc::client
