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

#include <boost/asio/awaitable.hpp>

#include <silkworm/lightclient/sentinel/sentinel_server.hpp>
#include <silkworm/lightclient/types/types.hpp>
#include <silkworm/lightclient/util/hash32.hpp>

namespace silkworm::cl::sentinel {

using boost::asio::awaitable;
using LightClientBootstrapPtr = std::shared_ptr<cl::LightClientBootstrap>;

class Client {
  public:
    virtual ~Client() = default;

    virtual awaitable<void> start() = 0;

    virtual awaitable<LightClientBootstrapPtr> bootstrap_request_v1(const Hash32& root) = 0;
};

class LocalClient : public Client {
  public:
    explicit LocalClient(Server* local_server);

    awaitable<void> start() override;

    awaitable<LightClientBootstrapPtr> bootstrap_request_v1(const Hash32& root) override;

  private:
    Server* local_server_;
};

class RemoteClient : public Client {
  public:
    awaitable<void> start() override;

    awaitable<LightClientBootstrapPtr> bootstrap_request_v1(const Hash32& root) override;
};

}  // namespace silkworm::cl::sentinel
