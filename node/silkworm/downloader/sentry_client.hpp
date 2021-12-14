/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_SENTRY_CLIENT_HPP
#define SILKWORM_SENTRY_CLIENT_HPP

#include <p2psentry/sentry.grpc.pb.h>

#include <silkworm/chain/identity.hpp>
#include <silkworm/concurrency/active_component.hpp>
#include <silkworm/downloader/internals/grpc_sync_client.hpp>
#include <silkworm/downloader/internals/sentry_type_casts.hpp>
#include <silkworm/downloader/internals/types.hpp>

namespace silkworm {

/*
 * SentryClient is a client to the external Sentry
 * It connects to the Sentry, send rpc and receive reply.
 */

/*
 * A client to connect to a remote sentry
 * The remote sentry must implement the ethereum p2p protocol and must have an interface specified by sentry.proto
 * SentryClient uses gRPC/protobuf to communicate with the remote sentry.
 */
class SentryClient : public rpc::Client<sentry::Sentry>, public ActiveComponent {
  public:
    using base_t = rpc::Client<sentry::Sentry>;
    using subscriber_t = std::function<void(const sentry::InboundMessage&)>;

    explicit SentryClient(const std::string& sentry_addr);  // connect to the remote sentry
    SentryClient(const SentryClient&) = delete;
    SentryClient(SentryClient&&) = delete;

    void set_status(Hash head_hash, BigInt head_td, const ChainIdentity&);  // init the remote sentry
    void hand_shake();  // needed by the remote sentry, also check the protocol version

    using base_t::exec_remotely;  // exec_remotely(SentryRpc& rpc) sends a rpc request to the remote sentry

    enum Scope { BlockRequests = 0x01, BlockAnnouncements = 0x02, Other = 0x04 };
    // enum values enable bit masking, for example: cope = BlockRequests & BlockAnnouncements

    void subscribe(Scope, subscriber_t callback);  // subscribe with sentry to receive messages

    /*[[long_running]]*/ void execution_loop() override;  // do a long-running loop to wait for messages
    /*[[long_running]]*/ void stats_receiving_loop();     // do a long-running loop to wait for peer statistics

    static Scope scope(const sentry::InboundMessage& message);  // find the scope of the message

  protected:
    void publish(const sentry::InboundMessage&);  // notifying registered subscribers

    std::map<Scope, std::list<subscriber_t>> subscribers_;  // todo: optimize
};

// custom exception
class SentryClientException : public std::runtime_error {
  public:
    explicit SentryClientException(const std::string& cause) : std::runtime_error(cause) {}
};

}  // namespace silkworm
#endif  // SILKWORM_SENTRY_CLIENT_HPP
