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

#include "ping_handler.hpp"

#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/message_expiration.hpp>

#include "pong_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::ping {

Task<void> PingHandler::handle(
    PingMessage message,
    boost::asio::ip::udp::endpoint sender_endpoint,
    Bytes ping_packet_hash,
    MessageSender& sender) {
    if (is_expired_message_expiration(message.expiration)) {
        co_return;
    }

    auto& recipient = sender_endpoint;
    PongMessage pong{
        recipient,
        ping_packet_hash,
        make_message_expiration(),
    };

    try {
        co_await sender.send_pong(std::move(pong), recipient);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled)
            throw;
        log::Warning("disc_v4") << "PingHandler::handle failed to reply"
                                << " to " << recipient
                                << " due to exception: " << ex.what();
    }
}

}  // namespace silkworm::sentry::discovery::disc_v4::ping
