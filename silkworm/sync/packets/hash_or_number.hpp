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

#pragma once

#include <variant>

#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/sync/internals/types.hpp>

namespace silkworm {

// HashOrNumber is a variant of Hash and BlockNum
// It uses struct in place of "using", to obtain a strong type and avoid overload resolution ambiguities
// in the rlp encoding/decoding functions
struct HashOrNumber : public std::variant<Hash, BlockNum> {};

// HashOrNumber rlp encoding/decoding
namespace rlp {

    inline void encode(Bytes& to, const HashOrNumber& from) {
        if (std::holds_alternative<Hash>(from)) {
            rlp::encode(to, std::get<Hash>(from));
        } else {
            rlp::encode(to, std::get<BlockNum>(from));
        }
    }

    inline size_t length(const HashOrNumber& from) {
        if (std::holds_alternative<Hash>(from)) {
            return rlp::length(std::get<Hash>(from));
        }
        return rlp::length(std::get<BlockNum>(from));
    }

    inline DecodingResult decode(ByteView& from, HashOrNumber& to, Leftover mode = Leftover::kProhibit) noexcept {
        ByteView copy(from);           // a copy because we need only decode header and not consume it
        auto h = decode_header(copy);  // so we can use full implementation of decode below
        if (!h) {
            return tl::unexpected{h.error()};
        }
        if (h->list) {
            return tl::unexpected{DecodingError::kUnexpectedList};
        }

        if (h->payload_length == 32) {
            Hash hash;
            if (DecodingResult res = rlp::decode(from, static_cast<evmc::bytes32&>(hash), mode); !res) {
                return res;
            }
            to = {hash};
        } else if (h->payload_length <= 8) {
            BlockNum block_num = 0;
            if (DecodingResult res = rlp::decode(from, block_num, mode); !res) {
                return res;
            }
            to = {block_num};
        } else {
            return tl::unexpected{DecodingError::kUnexpectedLength};
        }
        return {};
    }

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const HashOrNumber& packet) {
    if (std::holds_alternative<Hash>(packet))
        os << std::get<Hash>(packet).to_hex();
    else
        os << std::get<BlockNum>(packet);
    return os;
}

}  // namespace silkworm
