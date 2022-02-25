/*
   Copyright 2021-2022 The Silkworm Authors

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

// types
#include <silkworm/downloader/internals/types.hpp>

#include "BlockBodiesPacket.hpp"
#include "BlockHeadersPacket.hpp"
#include "GetBlockBodiesPacket.hpp"
#include "GetBlockHeadersPacket.hpp"
#include "NewBlockHashesPacket.hpp"
#include "NewBlockPacket.hpp"

// generic implementations (must follow types)
#include <silkworm/rlp/decode.hpp>

#include "RLPEth66PacketCoding.hpp"

// specific implementations
namespace silkworm::rlp {

template <>
DecodingResult decode(ByteView& from, Hash& to) noexcept {
    return rlp::decode(from, dynamic_cast<evmc::bytes32&>(to));
}

template <>
DecodingResult decode(ByteView& from, BlockBodiesPacket& to) noexcept {
    return rlp::decode_vector(from, to);
}

template <>
DecodingResult decode(ByteView& from, BlockHeadersPacket& to) noexcept {
    return rlp::decode_vector(from, to);
}

template <>
DecodingResult decode(ByteView& from, GetBlockBodiesPacket& to) noexcept {
    return rlp::decode_vector(from, to);
}

template <>
DecodingResult decode(ByteView& from, NewBlockHash& to) noexcept {
    auto [rlp_head, err0]{decode_header(from)};
    if (err0 != DecodingResult::kOk) {
        return err0;
    }
    if (!rlp_head.list) {
        return DecodingResult::kUnexpectedString;
    }

    uint64_t leftover{from.length() - rlp_head.payload_length};

    if (DecodingResult err{rlp::decode(from, to.hash)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{rlp::decode(from, to.number)}; err != DecodingResult::kOk) {
        return err;
    }

    return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
}

template <>
DecodingResult decode(ByteView& from, NewBlockHashesPacket& to) noexcept {
    return rlp::decode_vector(from, to);
}

template <>
DecodingResult decode(ByteView& from, NewBlockPacket& to) noexcept {
    auto [rlp_head, err0]{decode_header(from)};
    if (err0 != DecodingResult::kOk) {
        return err0;
    }
    if (!rlp_head.list) {
        return DecodingResult::kUnexpectedString;
    }

    uint64_t leftover{from.length() - rlp_head.payload_length};

    if (DecodingResult err{rlp::decode(from, to.block)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{rlp::decode(from, to.td)}; err != DecodingResult::kOk) {
        return err;
    }

    return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
}

template <>
DecodingResult decode(ByteView& from, GetBlockHeadersPacket66& to) noexcept {
    return rlp::decode_eth66_packet(from, to);
}

template <>
DecodingResult decode(ByteView& from, BlockBodiesPacket66& to) noexcept {
    return rlp::decode_eth66_packet(from, to);
}

template <>
DecodingResult decode(ByteView& from, BlockHeadersPacket66& to) noexcept {
    return rlp::decode_eth66_packet(from, to);
}

template <>
DecodingResult decode(ByteView& from, GetBlockBodiesPacket66& to) noexcept {
    return rlp::decode_eth66_packet(from, to);
}

template <>
DecodingResult decode(ByteView& from, GetBlockHeadersPacket& to) noexcept {
    using namespace rlp;

    auto [rlp_head, err0]{decode_header(from)};
    if (err0 != DecodingResult::kOk) {
        return err0;
    }
    if (!rlp_head.list) {
        return DecodingResult::kUnexpectedString;
    }

    uint64_t leftover{from.length() - rlp_head.payload_length};

    if (DecodingResult err{rlp::decode(from, to.origin)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{rlp::decode(from, to.amount)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{rlp::decode(from, to.skip)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{rlp::decode(from, to.reverse)}; err != DecodingResult::kOk) {
        return err;
    }

    return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
}

}  // namespace silkworm::rlp
