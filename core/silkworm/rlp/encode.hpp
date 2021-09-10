/*
   Copyright 2020-2021 The Silkworm Authors

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

// RLP encoding functions as per
// https://eth.wiki/en/fundamentals/rlp

#ifndef SILKWORM_RLP_ENCODE_HPP_
#define SILKWORM_RLP_ENCODE_HPP_

#include <optional>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>

namespace silkworm {

struct BlockBody;
struct BlockHeader;
struct Block;
struct Log;
struct Receipt;
struct AccessListEntry;
struct Transaction;

namespace rlp {

    struct Header {
        bool list{false};
        uint64_t payload_length{0};
    };

    constexpr uint8_t kEmptyStringCode{0x80};
    constexpr uint8_t kEmptyListCode{0xC0};

    void encode_header(Bytes& to, Header header);

    void encode(Bytes& to, const evmc::bytes32&);
    void encode(Bytes& to, ByteView);
    void encode(Bytes& to, uint64_t);
    void encode(Bytes& to, const intx::uint256&);

    void encode(Bytes& to, const BlockBody&);
    void encode(Bytes& to, const BlockHeader&, bool for_sealing = false);
    void encode(Bytes& to, const Block&);
    void encode(Bytes& to, const Log&);
    void encode(Bytes& to, const Receipt&);
    void encode(Bytes& to, const AccessListEntry&);
    void encode(Bytes& to, const Transaction&);

    size_t length_of_length(uint64_t payload_length);

    size_t length(ByteView);
    size_t length(uint64_t) noexcept;
    size_t length(const intx::uint256&);

    size_t length(const BlockHeader&);
    size_t length(const BlockBody&);
    size_t length(const Block&);
    size_t length(const Log&);
    size_t length(const AccessListEntry&);
    size_t length(const Transaction&);

    template <class T>
    size_t length(const std::vector<T>& v) {
        size_t payload_length{0};
        for (const T& x : v) {
            payload_length += length(x);
        }
        return length_of_length(payload_length) + payload_length;
    }

    template <class T>
    void encode(Bytes& to, const std::vector<T>& v) {
        Header h{true, 0};
        for (const T& x : v) {
            h.payload_length += length(x);
        }
        encode_header(to, h);
        for (const T& x : v) {
            encode(to, x);
        }
    }
}  // namespace rlp

}  // namespace silkworm

#endif  // SILKWORM_RLP_ENCODE_HPP_
