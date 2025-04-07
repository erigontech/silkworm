// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
struct HashOrNumber : public std::variant<Hash, BlockNum> {
    std::string to_string() const;
};

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
    os << packet.to_string();
    return os;
}

inline std::string HashOrNumber::to_string() const {
    const auto& packet = *this;
    std::stringstream os;

    if (std::holds_alternative<Hash>(packet))
        os << std::get<Hash>(packet).to_hex();
    else
        os << std::get<BlockNum>(packet);
    return os.str();
}

}  // namespace silkworm
