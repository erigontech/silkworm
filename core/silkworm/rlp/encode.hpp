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

namespace silkworm::rlp {

struct Header {
    bool list{false};
    size_t payload_length{0};
};

inline constexpr uint8_t kEmptyStringCode{0x80};
inline constexpr uint8_t kEmptyListCode{0xC0};

void encode_header(Bytes& to, Header header);

void encode(Bytes& to, ByteView);
void encode(Bytes& to, uint64_t);
void encode(Bytes& to, const intx::uint256&);

size_t length_of_length(uint64_t payload_length);

size_t length(ByteView);
size_t length(uint64_t) noexcept;
size_t length(const intx::uint256&);

}  // namespace silkworm::rlp

#endif  // SILKWORM_RLP_ENCODE_HPP_
