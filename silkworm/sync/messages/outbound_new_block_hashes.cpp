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

#include "outbound_new_block_hashes.hpp"

#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {

OutboundNewBlockHashes::OutboundNewBlockHashes(bool is_first_sync) : is_first_sync_{is_first_sync} {}

void OutboundNewBlockHashes::execute(db::DataStoreRef, HeaderChain& hc, BodySequence&, SentryClient& sentry) {
    auto& announces_to_do = hc.announces_to_do();

    if (is_first_sync_) {
        announces_to_do.clear();  // We don't want to send announces to peers during first sync
        return;
    }

    if (announces_to_do.empty()) {
        SILK_TRACE << "No OutboundNewBlockHashes (announcements) message to send";
        return;
    }

    for (auto& announce : announces_to_do) {
        packet_.emplace_back(NewBlockHash{announce.hash, announce.block_num});
    }

    SILK_TRACE << "Sending message OutboundNewBlockHashes (announcements) with send_message_to_all, content:"
               << packet_;

    try {
        [[maybe_unused]] auto peers = sentry.send_message_to_all(*this);

        SILK_TRACE << "Received sentry result of OutboundNewBlockHashes: " << std::to_string(peers.size()) + " peer(s)";

        announces_to_do.clear();  // clear announces from the queue
    } catch (const std::exception& e) {
        SILK_WARN << "OutboundNewBlockHashes failed send_message_to_all error: " << e.what();
    }
}

Bytes OutboundNewBlockHashes::message_data() const {
    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    return rlp_encoding;
}

std::string OutboundNewBlockHashes::content() const {
    if (packet_.empty()) return "- no block hash announcements to do, not sent -";
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm
