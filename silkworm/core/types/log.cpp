// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "log.hpp"

#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm::rlp {

static Header header(const Log& l) {
    Header h;
    h.list = true;
    h.payload_length = kAddressLength + 1;
    h.payload_length += length(l.topics);
    h.payload_length += length(l.data);
    return h;
}

size_t length(const Log& l) {
    Header h{header(l)};
    return length_of_length(h.payload_length) + h.payload_length;
}

void encode(Bytes& to, const Log& l) {
    encode_header(to, header(l));
    encode(to, l.address);
    encode(to, l.topics);
    encode(to, l.data);
}

}  // namespace silkworm::rlp
