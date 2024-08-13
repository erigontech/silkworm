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

#include <cstddef>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/decoding_result.hpp>
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/rlp/header.hpp>
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
