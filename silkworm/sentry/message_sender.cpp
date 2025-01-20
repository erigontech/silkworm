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

#include "message_sender.hpp"

#include <memory>

#include <silkworm/infra/common/log.hpp>

#include "rlpx/peer.hpp"

namespace silkworm::sentry {

Task<void> MessageSender::run(PeerManager& peer_manager) {
    try {
        // loop until receive() throws a cancelled exception
        while (true) {
            auto call = co_await send_message_channel_.receive();

            api::router::SendMessageCall::PeerKeys sent_peer_keys;

            auto sender = [&message = call.message(), &sent_peer_keys, peer_filter = call.peer_filter()](const std::shared_ptr<rlpx::Peer>& peer) {
                auto key_opt = peer->peer_public_key();
                if (key_opt && (!peer_filter.peer_public_key || (key_opt.value() == peer_filter.peer_public_key.value()))) {
                    sent_peer_keys.push_back(key_opt.value());
                    rlpx::Peer::post_message(peer, message);
                }
            };

            auto max_peers = call.peer_filter().max_peers;
            if (max_peers && (max_peers.value() > 0) && !call.peer_filter().peer_public_key) {
                co_await peer_manager.enumerate_random_peers(max_peers.value(), sender);
            } else {
                co_await peer_manager.enumerate_peers(sender);
            }

            call.set_result(std::move(sent_peer_keys));
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::system::errc::operation_canceled) {
            SILK_WARN_M("sentry") << "MessageSender::run unexpected end [operation_canceled]";
        } else {
            SILK_CRIT_M("sentry") << "MessageSender::run unexpected end [" + std::string{se.what()} + "]";
        }
        throw se;
    }
}

}  // namespace silkworm::sentry
