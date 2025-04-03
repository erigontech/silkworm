// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "withdrawal.hpp"

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/types/address.hpp>

namespace silkworm::rlp {

static Header header(const Withdrawal& w) {
    Header h{.list = true};
    h.payload_length += length(w.index);
    h.payload_length += length(w.validator_index);
    h.payload_length += length(w.address);
    h.payload_length += length(w.amount);
    return h;
}

size_t length(const Withdrawal& w) {
    const Header rlp_head{header(w)};
    return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
}

void encode(Bytes& to, const Withdrawal& w) {
    encode_header(to, header(w));
    encode(to, w.index);
    encode(to, w.validator_index);
    encode(to, w.address);
    encode(to, w.amount);
}

DecodingResult decode(ByteView& from, Withdrawal& to, Leftover mode) noexcept {
    return decode(from, mode, to.index, to.validator_index, to.address.bytes, to.amount);
}

}  // namespace silkworm::rlp
