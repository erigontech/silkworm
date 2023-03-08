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

#include <boost/asio/awaitable.hpp>

#include <silkworm/node/rpc/server/server_config.hpp>
#include <silkworm/sentry/api/router/service_router.hpp>

namespace silkworm::sentry::rpc {

class ServerImpl;

class Server final {
  public:
    explicit Server(
        const silkworm::rpc::ServerConfig& config,
        api::router::ServiceRouter router);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    boost::asio::awaitable<void> async_run();

  private:
    std::unique_ptr<ServerImpl> p_impl_;
};

}  // namespace silkworm::sentry::rpc
