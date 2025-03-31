// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "receipt.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>

namespace silkworm::rlp {

static Header header(const Receipt& r) {
    Header h;
    h.list = true;
    h.payload_length = 1;
    h.payload_length += length(r.cumulative_gas_used);
    h.payload_length += length(r.bloom);
    h.payload_length += length(r.logs);
    return h;
}

void encode(Bytes& to, const Receipt& r) {
    if (r.type != TransactionType::kLegacy) {
        to.push_back(static_cast<uint8_t>(r.type));
    }
    encode_header(to, header(r));
    encode(to, r.success);
    encode(to, r.cumulative_gas_used);
    encode(to, r.bloom);
    encode(to, r.logs);
}

}  // namespace silkworm::rlp
