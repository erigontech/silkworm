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

#include "withdrawal.hpp"

#include <silkworm/rlp/encode.hpp>

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

template <>
DecodingResult decode(ByteView& from, Withdrawal& to) noexcept {
    const auto rlp_head{decode_header(from)};
    if (!rlp_head) {
        return tl::unexpected{rlp_head.error()};
    }
    if (!rlp_head->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }
    uint64_t leftover{from.length() - rlp_head->payload_length};

    if (DecodingResult res{decode(from, to.index)}; !res) {
        return res;
    }
    if (DecodingResult res{decode(from, to.validator_index)}; !res) {
        return res;
    }
    if (DecodingResult res{decode(from, to.address.bytes)}; !res) {
        return res;
    }
    if (DecodingResult res{decode(from, to.amount)}; !res) {
        return res;
    }

    if (from.length() != leftover) {
        return tl::unexpected{DecodingError::kListLengthMismatch};
    }
    return {};
}

}  // namespace silkworm::rlp
