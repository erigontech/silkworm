// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/signals2.hpp>

#include <silkworm/infra/concurrency/task_group.hpp>
#include <silkworm/sentry/api/common/message_from_peer.hpp>
#include <silkworm/sentry/api/common/peer_event.hpp>
#include <silkworm/sentry/api/common/sentry_client.hpp>
#include <silkworm/sync/internals/types.hpp>
#include <silkworm/sync/messages/inbound_message.hpp>
#include <silkworm/sync/messages/outbound_message.hpp>

namespace silkworm {

/*
 * A SentryClient wrapper for the sync module.
 */
class SentryClient {
  public:
    explicit SentryClient(
        const boost::asio::any_io_executor& executor,
        std::shared_ptr<silkworm::sentry::api::SentryClient> sentry_client);

    SentryClient(const SentryClient&) = delete;
    SentryClient(SentryClient&&) = delete;

    // sending messages
    using PeerIds = std::vector<PeerId>;

    Task<SentryClient::PeerIds> send_message_by_id_async(const OutboundMessage& outbound_message, const PeerId& peer_id);
    PeerIds send_message_by_id(const OutboundMessage& message, const PeerId& peer_id);

    Task<PeerIds> send_message_to_random_peers_async(const OutboundMessage& message, size_t max_peers);
    PeerIds send_message_to_random_peers(const OutboundMessage& message, size_t max_peers);

    Task<PeerIds> send_message_to_all_async(const OutboundMessage& message);
    PeerIds send_message_to_all(const OutboundMessage& message);

    Task<PeerIds> send_message_by_min_block_async(const OutboundMessage& message, BlockNum min_block, size_t max_peers);
    PeerIds send_message_by_min_block(const OutboundMessage& message, BlockNum min_block, size_t max_peers);

    Task<void> peer_min_block_async(const PeerId& peer_id, BlockNum min_block);
    void peer_min_block(const PeerId& peer_id, BlockNum min_block);

    // receiving messages
    using Subscriber = void(std::shared_ptr<InboundMessage>);
    boost::signals2::signal<Subscriber> announcements_subscription;  // subscription to headers & bodies announcements
    boost::signals2::signal<Subscriber> requests_subscription;       // subscription to headers & bodies requests
    boost::signals2::signal<Subscriber> rest_subscription;           // subscription to everything else

    // reports received message sizes
    boost::signals2::signal<void(size_t)> received_message_size_subscription;

    // reports if a malformed message was received
    boost::signals2::signal<void()> malformed_message_subscription;

    // ask the remote sentry for active peers
    Task<uint64_t> count_active_peers_async();
    uint64_t count_active_peers();

    // ask the remote sentry for peer info
    Task<std::string> request_peer_info_async(PeerId peer_id);
    std::string request_peer_info(PeerId peer_id);

    Task<void> penalize_peer_async(PeerId peer_id, Penalty penalty);
    void penalize_peer(PeerId peer_id, Penalty penalty);

    uint64_t active_peers();  // return cached peers count

    // receive messages and peer events
    Task<void> async_run();

    static constexpr seconds_t kRequestDeadline = std::chrono::seconds(30);          // time beyond which the remote sentry
                                                                                     // considers an answer lost
    static constexpr milliseconds_t kNoPeerDelay = std::chrono::milliseconds(3000);  // chosen delay when no peer
                                                                                     // accepted the last request
    static constexpr size_t kPerPeerMaxOutstandingRequests = 4;                      // max number of outstanding requests per peer

  protected:
    Task<void> receive_messages();
    Task<void> receive_peer_events();

    // notifying registered subscribers
    Task<void> publish(const silkworm::sentry::api::MessageFromPeer& message_from_peer);

    boost::asio::any_io_executor executor_;
    std::shared_ptr<silkworm::sentry::api::SentryClient> sentry_client_;
    concurrency::TaskGroup tasks_;

    std::atomic<uint64_t> active_peers_{0};
};

}  // namespace silkworm
