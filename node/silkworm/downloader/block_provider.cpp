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

#include "block_provider.hpp"

#include <silkworm/common/log.hpp>

#include "internals/header_retrieval.hpp"
#include "rpc/ReceiveMessages.hpp"
#include "rpc/SetStatus.hpp"

namespace silkworm {

BlockProvider::BlockProvider(SentryClient& sentry, Db::ReadOnlyAccess db_access, ChainIdentity chain_identity)
    : chain_identity_(std::move(chain_identity)), db_access_{db_access}, sentry_{sentry} {}

BlockProvider::~BlockProvider() {
    stop();
    log::Error() << "BlockProvider destroyed";
}

void BlockProvider::send_status() {
    HeaderRetrieval headers(db_access_);
    auto [head_hash, head_td] = headers.head_hash_and_total_difficulty();

    rpc::SetStatus set_status(chain_identity_, head_hash, head_td);
    sentry_.exec_remotely(set_status);

    log::Trace() << "BlockProvider, send_status ok";
    sentry::SetStatusReply reply = set_status.reply();

    sentry::Protocol supported_protocol = reply.protocol();
    if (supported_protocol != sentry::Protocol::ETH66) {
        log::Critical() << "BlockProvider: sentry do not support eth/66 protocol, is_stopping...";
        sentry_.stop();
        throw BlockProviderException("BlockProvider exception, cause: sentry do not support eth/66 protocol");
    }
}

void BlockProvider::process_message(std::shared_ptr<InboundMessage> message) {
    log::Info() << "BlockProvider processing message " << *message;

    message->execute();
}

void BlockProvider::execution_loop() {
    try {
        send_status();

        rpc::ReceiveMessages receive_messages(rpc::ReceiveMessages::Scope::BlockRequests);
        sentry_.exec_remotely(receive_messages);

        while (!is_stopping() && !sentry_.is_stopping() && receive_messages.receive_one_reply()) {
            auto message = InboundBlockRequestMessage::make(receive_messages.reply(), db_access_, sentry_);

            process_message(message);
        }

        log::Warning() << "BlockProvider execution_loop is_stopping...";
    } catch (const std::exception& e) {
        log::Error() << "BlockProvider execution_loop is_stopping due to exception: " << e.what();
        stop();
        sentry_.stop();
    }
}

}  // namespace silkworm
