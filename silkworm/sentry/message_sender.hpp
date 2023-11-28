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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/sentry/api/router/send_message_call.hpp>

#include "peer_manager.hpp"

namespace silkworm::sentry {

class MessageSender {
  public:
    explicit MessageSender(const boost::asio::any_io_executor& executor)
        : send_message_channel_(executor) {}

    concurrency::Channel<api::router::SendMessageCall>& send_message_channel() {
        return send_message_channel_;
    }

    Task<void> run(PeerManager& peer_manager);

  private:
    concurrency::Channel<api::router::SendMessageCall> send_message_channel_;
};

}  // namespace silkworm::sentry
