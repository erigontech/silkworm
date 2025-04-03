// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "body_segment.hpp"

#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::snapshots {

void encode_word_from_body(Bytes& word, const BlockBodyForStorage& body) {
    word = body.encode();
}

void decode_word_into_body(ByteView word, BlockBodyForStorage& body) {
    const auto result = decode_stored_block_body(word, body);
    success_or_throw(result, "decode_word_into_body: decode_stored_block_body error");
}

}  // namespace silkworm::snapshots
