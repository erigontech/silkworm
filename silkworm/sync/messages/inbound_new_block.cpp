// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "inbound_new_block.hpp"

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/internals/random_number.hpp>

namespace silkworm {

InboundNewBlock::InboundNewBlock(ByteView data, PeerId peer_id)
    : peer_id_(std::move(peer_id)),
      req_id_(chainsync::random_number.generate_one())  // for trace purposes
{
    success_or_throw(rlp::decode(data, packet_));
    SILK_TRACE << "Received message " << *this;
}

void InboundNewBlock::execute(db::DataStoreRef, HeaderChain&, BodySequence& bs, SentryClient&) {
    SILK_TRACE << "Processing message " << *this;

    // todo: complete implementation
    /*
    // use packet_.td ?
    hc.accept_header(packet_.block.header); // process as single header segment
    */
    bs.accept_new_block(packet_.block, peer_id_);  // add to prefetched bodies
}

uint64_t InboundNewBlock::req_id() const { return req_id_; }

std::string InboundNewBlock::content() const {
    std::stringstream content;
    log::prepare_for_logging(content);
    content << packet_;
    return content.str();
}

}  // namespace silkworm
