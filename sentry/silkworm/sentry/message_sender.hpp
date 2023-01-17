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

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include <silkworm/sentry/common/channel.hpp>
#include <silkworm/sentry/rlpx/client.hpp>
#include <silkworm/sentry/rlpx/server.hpp>
#include <silkworm/sentry/rpc/common/send_message_call.hpp>

#include "peer_manager.hpp"

namespace silkworm::sentry {

class MessageSender {
  public:
    explicit MessageSender(boost::asio::io_context& io_context)
        : send_message_channel_(io_context) {}

    common::Channel<rpc::common::SendMessageCall>& send_message_channel() {
        return send_message_channel_;
    }

    boost::asio::awaitable<void> start(PeerManager& peer_manager);

  private:
    common::Channel<rpc::common::SendMessageCall> send_message_channel_;
};

}  // namespace silkworm::sentry
