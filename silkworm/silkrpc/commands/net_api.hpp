/*
   Copyright 2020 The Silkrpc Authors

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
#include <vector>

#include <silkworm/silkrpc/config.hpp> // NOLINT(build/include_order)

#include <boost/asio/awaitable.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/types/log.hpp>
#include <silkworm/silkrpc/ethbackend/backend.hpp>
#include <silkworm/silkrpc/common/log.hpp>

namespace silkrpc::http { class RequestHandler; }

namespace silkrpc::commands {

class NetRpcApi {
public:
    explicit NetRpcApi(std::unique_ptr<ethbackend::BackEnd>& backend) : backend_(backend) {}
    virtual ~NetRpcApi() = default;

    NetRpcApi(const NetRpcApi&) = delete;
    NetRpcApi& operator=(const NetRpcApi&) = delete;

protected:
    boost::asio::awaitable<void> handle_net_listening(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_net_peer_count(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_net_version(const nlohmann::json& request, nlohmann::json& reply);

private:
    friend class silkrpc::http::RequestHandler;

    std::unique_ptr<ethbackend::BackEnd>& backend_;
};
} // namespace silkrpc::commands

