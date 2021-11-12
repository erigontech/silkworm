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

#include "OutboundNewBlockHashes.hpp"

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/rpc/SendMessageToAll.hpp>
#include <silkworm/rlp/encode_vector.hpp>

namespace silkworm {

OutboundNewBlockHashes::OutboundNewBlockHashes(WorkingChain& wc, SentryClient& s) : working_chain_(wc), sentry_(s) {}

void OutboundNewBlockHashes::execute() {
    using namespace std::literals::chrono_literals;

    auto& announces_to_do = working_chain_.announces_to_do();

    for (auto& announce : announces_to_do) {
        // packet_.emplace_back(announce.hash, announce.number); // requires c++20
        packet_.push_back({announce.hash, announce.number});
    }

    auto request = std::make_unique<sentry::OutboundMessageData>();  // create request

    request->set_id(sentry::MessageId::NEW_BLOCK_HASHES_66);

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    request->set_data(rlp_encoding.data(), rlp_encoding.length());  // copy

    SILKWORM_LOG(LogLevel::Trace) << "Sending message OutboundNewBlockHashes with send_message_to_all, content:"
                                  << packet_ << " \n";
    rpc::SendMessageToAll rpc{std::move(request)};

    seconds_t timeout = 1s;
    rpc.timeout(timeout);

    sentry_.exec_remotely(rpc);

    sentry::SentPeers peers = rpc.reply();
    SILKWORM_LOG(LogLevel::Trace) << "Received rpc result of OutboundNewBlockHashes " << packet_ << ": "
                                  << std::to_string(peers.peers_size()) + " peer(s)\n";

    announces_to_do.clear();  // clear announces from the queue
}

std::string OutboundNewBlockHashes::content() const {
    std::stringstream content;
    content << packet_;
    return content.str();
}

}  // namespace silkworm
