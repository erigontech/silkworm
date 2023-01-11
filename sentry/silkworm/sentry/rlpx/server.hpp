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

#include <functional>
#include <future>
#include <list>
#include <memory>
#include <string>
#include <utility>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/rpc/server/server_context_pool.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

#include "peer.hpp"
#include "protocol.hpp"

namespace silkworm::sentry::rlpx {

class Server final {
  public:
    Server(
        boost::asio::io_context& io_context,
        std::string host,
        uint16_t port);

    boost::asio::awaitable<void> start(
        silkworm::rpc::ServerContextPool& context_pool,
        common::EccKeyPair node_key,
        std::string client_id,
        std::function<std::unique_ptr<Protocol>()> protocol_factory);

    boost::asio::awaitable<void> enumerate_peers(std::function<boost::asio::awaitable<void>(Peer&)> callback);
    boost::asio::awaitable<void> enumerate_random_peers(size_t max_count, std::function<boost::asio::awaitable<void>(Peer&)> callback);

  private:
    boost::asio::awaitable<void> start_in_strand(
        silkworm::rpc::ServerContextPool& context_pool,
        common::EccKeyPair node_key,
        std::string client_id,
        std::function<std::unique_ptr<Protocol>()> protocol_factory);

    boost::asio::awaitable<void> enumerate_peers_in_strand(std::function<boost::asio::awaitable<void>(Peer&)> callback);
    boost::asio::awaitable<void> enumerate_random_peers_in_strand(size_t max_count, std::function<boost::asio::awaitable<void>(Peer&)> callback);

    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    std::string host_;
    uint16_t port_;

    std::list<std::pair<std::unique_ptr<Peer>, std::future<void>>> peers_;
};

}  // namespace silkworm::sentry::rlpx
