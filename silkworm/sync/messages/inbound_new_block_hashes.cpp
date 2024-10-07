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

#include "inbound_new_block_hashes.hpp"

#include <algorithm>

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/core/common/singleton.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/sentry_client.hpp>

#include "outbound_get_block_headers.hpp"

namespace silkworm {

InboundNewBlockHashes::InboundNewBlockHashes(ByteView data, PeerId peer_id)
    : peer_id_(std::move(peer_id)),
      req_id_(Singleton<RandomNumber>::instance().generate_one())  // for trace purposes
{
    success_or_throw(rlp::decode(data, packet_));
    SILK_TRACE << "Received message " << *this;
}

void InboundNewBlockHashes::execute(db::ROAccess, HeaderChain& hc, BodySequence&, SentryClient& sentry) {
    using namespace std;

    SILK_TRACE << "Processing message " << *this;

    BlockNum max = hc.top_seen_block_height();

    for (auto& new_block_hash : packet_) {
        Hash hash = new_block_hash.hash;

        // calculate top seen block height
        max = std::max(max, new_block_hash.number);

        // save announcement
        auto packet = hc.save_external_announce(hash);
        if (!packet) continue;

        // request header
        SILK_TRACE << "Replying to " << identify(*this) << " requesting header with send_message_by_id, content: " << *packet;

        try {
            OutboundGetBlockHeaders request_message{packet.value()};
            [[maybe_unused]] auto peers = sentry.send_message_by_id(request_message, peer_id_);

            SILK_TRACE << "Received sentry result of " << identify(*this) << ": "
                       << std::to_string(peers.size()) + " peer(s)";
        } catch (const boost::system::system_error& se) {
            SILK_TRACE << "Received error from sentry send_message_by_id for " << identify(*this) << " error: " << se.what();
        }
    }

    hc.top_seen_block_height(max);
}

uint64_t InboundNewBlockHashes::req_id() const { return req_id_; }

std::string InboundNewBlockHashes::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm