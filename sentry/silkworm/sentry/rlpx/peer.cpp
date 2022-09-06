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

#include "peer.hpp"

#include <boost/asio/error.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/common/log.hpp>

#include "auth/handshake.hpp"

namespace silkworm::sentry::rlpx {

boost::asio::awaitable<void> Peer::handle() {
    try {
        log::Debug() << "Peer::handle";

        auth::Handshake handshake{
            node_key_,
            client_id_,
            node_listen_port_,
            {"eth", 67},
            peer_public_key_,
        };
        auto message_stream = co_await handshake.execute(stream_);

        auto first_message = co_await message_stream.receive();
        log::Debug() << "Peer::handle first_message: " << int(first_message.id);

    } catch (const auth::Handshake::DisconnectError&) {
        // TODO: handle disconnect
        log::Debug() << "Peer::handle DisconnectError";
        co_return;
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::asio::error::eof) {
            // TODO: handle disconnect
            log::Debug() << "Peer::handle EOF";
            co_return;
        } else if (ex.code() == boost::asio::error::connection_reset) {
            // TODO: handle disconnect
            log::Debug() << "Peer::handle connection reset";
            co_return;
        }
        log::Error() << "Peer::handle system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error() << "Peer::handle exception: " << ex.what();
        throw;
    }
}

}  // namespace silkworm::sentry::rlpx
