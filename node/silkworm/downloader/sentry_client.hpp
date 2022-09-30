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

#include <atomic>

#include <boost/signals2.hpp>
#include <p2psentry/sentry.grpc.pb.h>

#include <silkworm/concurrency/active_component.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/downloader/internals/grpc_sync_client.hpp>
#include <silkworm/downloader/internals/sentry_type_casts.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/downloader/rpc/hand_shake.hpp>
#include <silkworm/downloader/rpc/receive_messages.hpp>
#include <silkworm/downloader/rpc/receive_peer_stats.hpp>

namespace silkworm {

/*
 * SentryClient is a client to connect to a remote sentry, send rpc and receive reply.
 * The remote sentry must implement the ethereum p2p protocol and must have an interface specified by sentry.proto
 * SentryClient uses gRPC/protobuf to communicate with the remote sentry.
 */
class SentryClient : public rpc::Client<sentry::Sentry>, public ActiveComponent {
  public:
    using base_t = rpc::Client<sentry::Sentry>;
    using subscriber_t = void(const sentry::InboundMessage&);

    explicit SentryClient(const std::string& sentry_addr, const db::ROAccess&, const ChainConfig&);  // connect to the remote sentry
    SentryClient(const SentryClient&) = delete;
    SentryClient(SentryClient&&) = delete;

    void set_status();              // init the remote sentry
    void hand_shake();              // hand_shake & check of the protocol version
    uint64_t count_active_peers();  // ask the remote sentry for active peers

    uint64_t active_peers();  // return cached peers count

    using base_t::exec_remotely;  // exec_remotely(SentryRpc& rpc) sends a rpc request to the remote sentry

    boost::signals2::signal<subscriber_t> announcements_subscription;  // subscription to headers & bodies announcements
    boost::signals2::signal<subscriber_t> requests_subscription;       // subscription to headers & bodies requests
    boost::signals2::signal<subscriber_t> rest_subscription;           // subscription to everything else

    bool stop() override;

    /*[[long_running]]*/ void execution_loop() override;  // do a long-running loop to wait for messages
    /*[[long_running]]*/ void stats_receiving_loop();     // do a long-running loop to wait for peer statistics

    static rpc::ReceiveMessages::Scope scope(const sentry::InboundMessage& message);  // find the scope of the message

  protected:
    void publish(const sentry::InboundMessage&);  // notifying registered subscribers
    void set_status(Hash head_hash, BigInt head_td, const ChainConfig&);

    const std::string sentry_addr_;
    db::ROAccess db_access_;
    const ChainConfig& chain_config_;

    std::shared_ptr<rpc::HandShake> handshake_;
    std::shared_ptr<rpc::ReceiveMessages> receive_messages_;
    std::shared_ptr<rpc::ReceivePeerStats> receive_peer_stats_;

    std::atomic<uint64_t> active_peers_{0};
};

// custom exception
class SentryClientException : public std::runtime_error {
  public:
    explicit SentryClientException(const std::string& cause) : std::runtime_error(cause) {}
};

}  // namespace silkworm
