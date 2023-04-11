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

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sentry/eth/message_id.hpp>
#include <silkworm/sync/internals/header_retrieval.hpp>

#include "messages/inbound_block_bodies.hpp"
#include "messages/inbound_block_headers.hpp"
#include "messages/inbound_get_block_bodies.hpp"
#include "messages/inbound_get_block_headers.hpp"
#include "messages/inbound_new_block.hpp"
#include "messages/inbound_new_block_hashes.hpp"

namespace silkworm {

using namespace boost::asio;

SentryClient::SentryClient(
    boost::asio::io_context& io_context,
    std::shared_ptr<silkworm::sentry::api::api_common::SentryClient> sentry_client,
    const db::ROAccess& db_access,
    const ChainConfig& chain_config)
    : io_context_{io_context},
      sentry_client_{std::move(sentry_client)},
      db_access_{db_access},
      chain_config_{chain_config} {
}

static std::unique_ptr<InboundMessage> decode_inbound_message(const silkworm::sentry::api::api_common::MessageFromPeer& message_from_peer) {
    using sentry::eth::MessageId;
    auto eth_message_id = sentry::eth::eth_message_id_from_common_id(message_from_peer.message.id);
    PeerId peer_id = message_from_peer.peer_public_key->serialized();
    ByteView raw_message{message_from_peer.message.data};
    switch (eth_message_id) {
        case MessageId::kGetBlockHeaders:
            return std::make_unique<InboundGetBlockHeaders>(raw_message, peer_id);
        case MessageId::kGetBlockBodies:
            return std::make_unique<InboundGetBlockBodies>(raw_message, peer_id);
        case MessageId::kNewBlockHashes:
            return std::make_unique<InboundNewBlockHashes>(raw_message, peer_id);
        case MessageId::kNewBlock:
            return std::make_unique<InboundNewBlock>(raw_message, peer_id);
        case MessageId::kBlockHeaders:
            return std::make_unique<InboundBlockHeaders>(raw_message, peer_id);
        case MessageId::kBlockBodies:
            return std::make_unique<InboundBlockBodies>(raw_message, peer_id);
        default:
            return {};
    }
}

static constexpr std::string_view kLogTitle{"sync::SentryClient"};

boost::asio::awaitable<void> SentryClient::publish(const silkworm::sentry::api::api_common::MessageFromPeer& message_from_peer) {
    using sentry::eth::MessageId;
    auto eth_message_id = sentry::eth::eth_message_id_from_common_id(message_from_peer.message.id);

    std::shared_ptr<InboundMessage> message;
    std::optional<PeerId> penalize_peer_id;
    try {
        message = std::shared_ptr(decode_inbound_message(message_from_peer));
    } catch (DecodingException& error) {
        PeerId peer_id = message_from_peer.peer_public_key->serialized();
        log::Warning(kLogTitle) << "received and ignored a malformed message, peer= " << human_readable_id(peer_id)
                                << ", msg-id= " << static_cast<int>(message_from_peer.message.id)
                                << " - " << error.what();
        penalize_peer_id = std::move(peer_id);
    }

    received_message_size_subscription(message_from_peer.message.data.size());

    if (penalize_peer_id) {
        malformed_message_subscription();
        co_await penalize_peer_async(penalize_peer_id.value(), BadBlockPenalty);
        co_return;
    }

    if (!message) {
        log::Warning(kLogTitle) << "InboundMessage " << static_cast<int>(eth_message_id) << " received but ignored";
        co_return;
    }

    switch (eth_message_id) {
        case MessageId::kGetBlockHeaders:
        case MessageId::kGetBlockBodies:
            requests_subscription(message);
            break;
        case MessageId::kBlockHeaders:
        case MessageId::kBlockBodies:
        case MessageId::kNewBlockHashes:
        case MessageId::kNewBlock:
            announcements_subscription(message);
            break;
        default:
            rest_subscription(message);
            break;
    }
}

static silkworm::sentry::api::api_common::MessageIdSet make_message_id_filter() {
    using namespace sentry::eth;
    silkworm::sentry::api::api_common::MessageIdSet ids = {
        common_message_id_from_eth_id(MessageId::kGetBlockHeaders),
        common_message_id_from_eth_id(MessageId::kGetBlockBodies),

        common_message_id_from_eth_id(MessageId::kBlockHeaders),
        common_message_id_from_eth_id(MessageId::kBlockBodies),
        common_message_id_from_eth_id(MessageId::kNewBlockHashes),
        common_message_id_from_eth_id(MessageId::kNewBlock),
    };
    return ids;
}

void SentryClient::set_status(BlockNum head_block_num, Hash head_hash, BigInt head_td, const ChainConfig& chain_config) {
    auto fork_block_numbers = chain_config.distinct_fork_numbers();
    auto best_block_hash = Bytes{ByteView{head_hash}};
    auto genesis_hash = ByteView{chain_config.genesis_hash.value()};

    silkworm::sentry::eth::StatusMessage status_message = {
        0,  // the eth protocol version is replaced on the sentry end
        chain_config.chain_id,
        head_td,
        best_block_hash,
        Bytes{genesis_hash},
        silkworm::sentry::eth::ForkId(genesis_hash, fork_block_numbers, head_block_num),
    };

    silkworm::sentry::eth::StatusData status_data = {
        std::move(fork_block_numbers),
        head_block_num,
        std::move(status_message),
    };

    co_spawn(io_context_, sentry_client_->service()->set_status(std::move(status_data)), use_future).get();

    SILK_TRACE << "SentryClient, set_status sent";
}

void SentryClient::set_status() {
    HeaderRetrieval headers(db_access_);
    auto [head_height, head_hash, head_td] = headers.head_info();
    headers.close();

    log::Debug("Chain/db status", {"head hash", head_hash.to_hex()});
    log::Debug("Chain/db status", {"head td", intx::to_string(head_td)});
    log::Debug("Chain/db status", {"head height", std::to_string(head_height)});

    set_status(head_height, head_hash, head_td, chain_config_);
}

void SentryClient::handshake() {
    auto supported_protocol = co_spawn(io_context_, sentry_client_->service()->handshake(), use_future).get();

    if (supported_protocol < 66) {
        log::Critical(kLogTitle) << "remote sentry do not support eth/66 protocol, stopping...";
        stop();
        throw SentryClientException("SentryClient exception, cause: sentry do not support eth/66 protocol");
    }
}

static sentry::common::Message sentry_message_from_outbound_message(const OutboundMessage& outbound_message) {
    return sentry::common::Message{
        sentry::eth::common_message_id_from_eth_id(outbound_message.eth_message_id()),
        outbound_message.message_data(),
    };
}

static SentryClient::PeerIds peer_ids_from_peer_keys(const silkworm::sentry::api::api_common::Service::PeerKeys& peer_keys) {
    SentryClient::PeerIds peer_ids;
    for (auto& peer_key : peer_keys) {
        peer_ids.push_back(peer_key.serialized());
    }
    return peer_ids;
}

SentryClient::PeerIds SentryClient::send_message_by_id(const OutboundMessage& outbound_message, const PeerId& peer_id) {
    auto message = sentry_message_from_outbound_message(outbound_message);
    auto peer_public_key = sentry::common::EccPublicKey::deserialize(peer_id);
    auto peer_keys = co_spawn(io_context_, sentry_client_->service()->send_message_by_id(std::move(message), std::move(peer_public_key)), use_future).get();
    return peer_ids_from_peer_keys(peer_keys);
}

SentryClient::PeerIds SentryClient::send_message_to_random_peers(const OutboundMessage& outbound_message, size_t max_peers) {
    auto message = sentry_message_from_outbound_message(outbound_message);
    auto peer_keys = co_spawn(io_context_, sentry_client_->service()->send_message_to_random_peers(std::move(message), max_peers), use_future).get();
    return peer_ids_from_peer_keys(peer_keys);
}

SentryClient::PeerIds SentryClient::send_message_to_all(const OutboundMessage& outbound_message) {
    auto message = sentry_message_from_outbound_message(outbound_message);
    auto peer_keys = co_spawn(io_context_, sentry_client_->service()->send_message_to_all(std::move(message)), use_future).get();
    return peer_ids_from_peer_keys(peer_keys);
}

SentryClient::PeerIds SentryClient::send_message_by_min_block(const OutboundMessage& outbound_message, BlockNum /*min_block*/, size_t max_peers) {
    auto message = sentry_message_from_outbound_message(outbound_message);
    auto peer_keys = co_spawn(io_context_, sentry_client_->service()->send_message_by_min_block(std::move(message), max_peers), use_future).get();
    return peer_ids_from_peer_keys(peer_keys);
}

void SentryClient::peer_min_block(const PeerId& peer_id, BlockNum /*min_block*/) {
    auto peer_public_key = sentry::common::EccPublicKey::deserialize(peer_id);
    co_spawn(io_context_, sentry_client_->service()->peer_min_block(std::move(peer_public_key)), use_future).get();
}

void SentryClient::execution_loop() {
    log::set_thread_name("sentry-recv   ");

    while (!is_stopping()) {
        try {
            connected_ = false;
            log::Info(kLogTitle) << "connecting ...";

            // send current status of the chain
            handshake();
            set_status();

            connected_ = true;
            connected_.notify_all();
            log::Info(kLogTitle) << "connected";

            // receive messages

            std::function<awaitable<void>(silkworm::sentry::api::api_common::MessageFromPeer)> consumer = [this](auto message_from_peer) -> awaitable<void> {
                if (!this->is_stopping()) {
                    co_await this->publish(message_from_peer);
                }
            };

            co_spawn(io_context_, sentry_client_->service()->messages(make_message_id_filter(), consumer), use_future).get();

        } catch (const std::exception& e) {
            if (!is_stopping()) log::Error(kLogTitle) << "exception: " << e.what();
        }
    }

    // note: do we need to handle connection loss with an outer loop that wait and then re-try hand_shake and so on?
    // (we would redo set_status & hand-shake too)
    log::Warning(kLogTitle) << "execution loop is stopping...";
    stop();

    connected_ = false;
    connected_.notify_all();
}

void SentryClient::stats_receiving_loop() {
    log::set_thread_name("sentry-stats  ");
    std::map<PeerId, std::string> peer_infos;

    while (!is_stopping()) {
        try {
            connected_.wait(false);

            // ask the remote sentry about the current active peers
            log::Info(kLogTitle) << count_active_peers() << " active peers";

            // receive stats

            std::function<awaitable<void>(silkworm::sentry::api::api_common::PeerEvent)> consumer = [this, &peer_infos](auto stat) -> awaitable<void> {
                if (this->is_stopping()) {
                    co_return;
                }

                auto peer_id = stat.peer_public_key->serialized();
                std::string event;
                std::string info;
                if (stat.event_id == silkworm::sentry::api::api_common::PeerEventId::kAdded) {
                    event = "connected";
                    active_peers_++;

                    info = co_await request_peer_info_async(peer_id);
                    peer_infos[peer_id] = info;
                } else {
                    event = "disconnected";
                    if (active_peers_ > 0) active_peers_--;

                    info = peer_infos[peer_id];
                    peer_infos.erase(peer_id);
                }

                log::Info(kLogTitle) << "Peer " << human_readable_id(peer_id)
                                     << " " << event
                                     << ", active " << active_peers()
                                     << ", info: " << info;
            };

            co_spawn(io_context_, sentry_client_->service()->peer_events(consumer), use_future).get();

        } catch (const std::exception& e) {
            if (!is_stopping()) log::Warning(kLogTitle) << "exception: " << e.what();
        }
    }

    log::Warning(kLogTitle) << "stats loop is stopping...";
    stop();
}

uint64_t SentryClient::count_active_peers() {
    size_t peer_count = co_spawn(io_context_, sentry_client_->service()->peer_count(), use_future).get();
    active_peers_.store(peer_count);
    return peer_count;
}

boost::asio::awaitable<std::string> SentryClient::request_peer_info_async(PeerId peer_id) {
    auto peer_public_key = sentry::common::EccPublicKey::deserialize(peer_id);
    auto peer_info_opt = co_await sentry_client_->service()->peer_by_id(std::move(peer_public_key));

    if (!peer_info_opt) {
        co_return "-info-not-found-";
    } else {
        auto peer_info = peer_info_opt.value();
        std::string info = "client_id=" + peer_info.client_id + " / enode_url=" + peer_info.url.to_string();
        co_return info;
    }
}

std::string SentryClient::request_peer_info(PeerId peer_id) {
    return co_spawn(io_context_, this->request_peer_info_async(std::move(peer_id)), use_future).get();
}

boost::asio::awaitable<void> SentryClient::penalize_peer_async(PeerId peer_id, Penalty penalty) {
    if (penalty == Penalty::NoPenalty) {
        co_return;
    }
    auto peer_public_key = sentry::common::EccPublicKey::deserialize(peer_id);
    co_await sentry_client_->service()->penalize_peer(std::move(peer_public_key));
}

void SentryClient::penalize_peer(PeerId peer_id, Penalty penalty) {
    co_spawn(io_context_, this->penalize_peer_async(std::move(peer_id), penalty), use_future).get();
}

uint64_t SentryClient::active_peers() {
    return active_peers_.load();
}

bool SentryClient::stop() {
    bool expected = Stoppable::stop();
    // TODO: stop futures
    return expected;
}

}  // namespace silkworm
