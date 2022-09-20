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

#include "sentry_client.hpp"

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/rpc/hand_shake.hpp>
#include <silkworm/downloader/rpc/peer_count.hpp>
#include <silkworm/downloader/rpc/receive_messages.hpp>
#include <silkworm/downloader/rpc/receive_peer_stats.hpp>
#include <silkworm/downloader/rpc/set_status.hpp>

namespace silkworm {

constexpr int kMaxReceiveMessageSize = 10_Mebi;  // reference: eth/66 protocol

static std::shared_ptr<grpc::Channel> create_custom_channel(const std::string& sentry_addr) {
    grpc::ChannelArguments custom_args{};
    custom_args.SetMaxReceiveMessageSize(kMaxReceiveMessageSize);
    return grpc::CreateCustomChannel(sentry_addr, grpc::InsecureChannelCredentials(), custom_args);
}

SentryClient::SentryClient(const std::string& sentry_addr)
    : base_t(create_custom_channel(sentry_addr)),
      receive_messages_(rpc::ReceiveMessages::Scope::BlockAnnouncements |
                        rpc::ReceiveMessages::Scope::BlockRequests) {
    log::Info() << "SentryClient, connecting to remote sentry...";
}

rpc::ReceiveMessages::Scope SentryClient::scope(const sentry::InboundMessage& message) {
    switch (message.id()) {
        case sentry::MessageId::BLOCK_HEADERS_66:
        case sentry::MessageId::BLOCK_BODIES_66:
        case sentry::MessageId::NEW_BLOCK_HASHES_66:
        case sentry::MessageId::NEW_BLOCK_66:
            return rpc::ReceiveMessages::Scope::BlockAnnouncements;
        case sentry::MessageId::GET_BLOCK_HEADERS_66:
        case sentry::MessageId::GET_BLOCK_BODIES_66:
            return rpc::ReceiveMessages::Scope::BlockRequests;
        default:
            return rpc::ReceiveMessages::Scope::Other;
    }
}

void SentryClient::publish(const sentry::InboundMessage& message) {
    switch (scope(message)) {
        case rpc::ReceiveMessages::Scope::BlockRequests:
            requests_subscription(message);
            break;
        case rpc::ReceiveMessages::Scope::BlockAnnouncements:
            announcements_subscription(message);
            break;
        default:
            rest_subscription(message);
    }
}

void SentryClient::set_status(Hash head_hash, BigInt head_td, const ChainConfig& chain_config) {
    rpc::SetStatus set_status{chain_config, head_hash, head_td};
    exec_remotely(set_status);
    SILK_TRACE << "SentryClient, set_status sent";
}

void SentryClient::hand_shake() {
    rpc::HandShake hand_shake;
    exec_remotely(hand_shake);

    SILK_TRACE << "SentryClient, hand_shake sent";
    sentry::HandShakeReply reply = hand_shake.reply();

    sentry::Protocol supported_protocol = reply.protocol();
    if (supported_protocol != sentry::Protocol::ETH66) {
        log::Critical() << "SentryClient: sentry do not support eth/66 protocol, is stopping...";
        stop();
        throw SentryClientException("SentryClient exception, cause: sentry do not support eth/66 protocol");
    }
}

void SentryClient::execution_loop() {
    log::set_thread_name("sentry-recv   ");

    try {
        // send a message subscription
        exec_remotely(receive_messages_);

        // receive messages
        while (!is_stopping() && receive_messages_.receive_one_reply()) {
            const auto& message = receive_messages_.reply();

            publish(message);
        }

    } catch (const std::exception& e) {
        if (!is_stopping()) log::Error() << "SentryClient execution loop aborted due to exception: " << e.what();
    }

    // note: do we need to handle connection loss with an outer loop that wait and then re-try hand_shake and so on?
    // (we would redo set_status & hand-shake too)
    log::Warning() << "SentryClient execution loop is stopping...";
    stop();
}

void SentryClient::stats_receiving_loop() {
    log::set_thread_name("sentry-stats  ");

    try {
        // send a stats subscription
        // rpc::ReceivePeerStats receive_peer_stats;
        exec_remotely(receive_peer_stats_);

        // ask the remote sentry about the current active peers
        count_active_peers();
        log::Info() << "SentryClient, " << active_peers_ << " active peers";

        // receive stats
        while (!is_stopping() && receive_peer_stats_.receive_one_reply()) {
            const sentry::PeerEvent& stat = receive_peer_stats_.reply();

            auto peerId = bytes_from_H512(stat.peer_id());
            const char* event = "";
            if (stat.event_id() == sentry::PeerEvent::Connect) {
                event = "connected";
                active_peers_++;
            } else {
                event = "disconnected";
                if (active_peers_ > 0) active_peers_--;  // workaround, to fix this we need to improve the interface
            }                                            // or issue a count_active_peers()

            log::Debug() << "Peer " << human_readable_id(peerId) << " " << event << ", active " << active_peers_;
        }

    } catch (const std::exception& e) {
        if (!is_stopping()) log::Error() << "SentryClient stats loop aborted due to exception: " << e.what();
    }

    log::Warning() << "SentryClient stats loop is stopping...";
    stop();
}

uint64_t SentryClient::count_active_peers() {
    using namespace std::chrono_literals;
    rpc::PeerCount rpc;

    rpc.timeout(1s);
    rpc.do_not_throw_on_failure();

    exec_remotely(rpc);

    if (!rpc.status().ok()) {
        SILK_TRACE << "Failure of rpc PeerCount: " << rpc.status().error_message();
        return 0;
    }

    sentry::PeerCountReply peers = rpc.reply();
    active_peers_.store(peers.count());

    return peers.count();
}

uint64_t SentryClient::active_peers() {
    return active_peers_.load();
}

bool SentryClient::stop() {
    bool expected = Stoppable::stop();
    receive_messages_.try_cancel();
    receive_peer_stats_.try_cancel();
    return expected;
}

}  // namespace silkworm
