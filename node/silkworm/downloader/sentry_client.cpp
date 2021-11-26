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

#include "sentry_client.hpp"

#include <silkworm/common/log.hpp>

#include "rpc/SetStatus.hpp"
#include "rpc/ReceiveMessages.hpp"

namespace silkworm {

SentryClient::SentryClient(std::string sentry_addr)
    : base_t(grpc::CreateChannel(sentry_addr, grpc::InsecureChannelCredentials())) {}

SentryClient::Scope SentryClient::scope(const sentry::InboundMessage& message) {
    switch (message.id()) {
        case sentry::MessageId::BLOCK_HEADERS_66:
        case sentry::MessageId::BLOCK_BODIES_66:
        case sentry::MessageId::NEW_BLOCK_HASHES_66:
        case sentry::MessageId::NEW_BLOCK_66:
            return SentryClient::Scope::BlockAnnouncements;
        case sentry::MessageId::GET_BLOCK_HEADERS_66:
        case sentry::MessageId::GET_BLOCK_BODIES_66:
            return SentryClient::Scope::BlockRequests;
        default:
            return SentryClient::Scope::Other;
    }
}

void SentryClient::subscribe(Scope scope, subscriber_t callback) { subscribers_[scope].push_back(std::move(callback)); }

void SentryClient::publish(const sentry::InboundMessage& message) {
    auto subscribers = subscribers_[scope(message)];
    for (auto& subscriber : subscribers) {
        subscriber(message);
    }
}

void SentryClient::set_status(Hash head_hash, BigInt head_td, const ChainIdentity& chain_identity) {
    rpc::SetStatus set_status{chain_identity, head_hash, head_td};
    exec_remotely(set_status);

    log::Info() << "SentryClient, set_status sent";
    sentry::SetStatusReply reply = set_status.reply();

    sentry::Protocol supported_protocol = reply.protocol();
    if (supported_protocol != sentry::Protocol::ETH66) {
        log::Critical() << "SentryClient: sentry do not support eth/66 protocol, is_stopping...";
        stop();
        throw SentryClientException("SentryClient exception, cause: sentry do not support eth/66 protocol");
    }
}

void SentryClient::execution_loop() {
    // send a message subscription
    rpc::ReceiveMessages message_subscription(Scope::BlockAnnouncements | Scope::BlockRequests);
    exec_remotely(message_subscription);

    // receive messages
    while (!is_stopping() && message_subscription.receive_one_reply()) {
        const auto& message = message_subscription.reply();

        // log::Trace() << "SentryClient received message " << *message;

        publish(message);
    }

    // note: do we need to handle connection loss retrying re-connect? (we would redo set_status too)

    log::Warning() << "SentryClient execution loop is stopping...";
}

}  // namespace silkworm