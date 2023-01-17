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
#include <list>
#include <memory>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/sentry/common/channel.hpp>
#include <silkworm/sentry/rlpx/client.hpp>
#include <silkworm/sentry/rlpx/peer.hpp>
#include <silkworm/sentry/rlpx/server.hpp>

namespace silkworm::sentry {

class PeerManager {
  public:
    PeerManager(boost::asio::io_context& io_context)
        : strand_(boost::asio::make_strand(io_context)) {}

    boost::asio::awaitable<void> start(rlpx::Server& server, rlpx::Client& client);

    using EnumeratePeersCallback = std::function<void(std::shared_ptr<rlpx::Peer>)>;

    boost::asio::awaitable<void> enumerate_peers(EnumeratePeersCallback callback);
    boost::asio::awaitable<void> enumerate_random_peers(size_t max_count, EnumeratePeersCallback callback);

  private:
    boost::asio::awaitable<void> start_in_strand(common::Channel<std::shared_ptr<rlpx::Peer>>& peer_channel);

    boost::asio::awaitable<void> enumerate_peers_in_strand(EnumeratePeersCallback callback);
    boost::asio::awaitable<void> enumerate_random_peers_in_strand(size_t max_count, EnumeratePeersCallback callback);

    std::list<std::shared_ptr<rlpx::Peer>> peers_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
};

}  // namespace silkworm::sentry
