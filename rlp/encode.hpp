/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_RLP_ENCODE_H_
#define SILKWORM_RLP_ENCODE_H_

#include <stddef.h>
#include <stdint.h>

#include <intx/intx.hpp>
#include <ostream>
#include <string_view>

namespace silkworm::rlp {

static constexpr uint8_t kEmptyStringCode = 0x80;
static constexpr uint8_t kEmptyListCode = 0xC0;

struct Header {
  bool list{false};
  uint64_t length{0};
};

void encode(std::ostream& to, Header header);

void encode(std::ostream& to, std::string_view s);
void encode(std::ostream& to, uint64_t n);
void encode(std::ostream& to, intx::uint256 n);

size_t length(Header header);

size_t length(std::string_view s);
size_t length(uint64_t n);
size_t length(intx::uint256 n);

}  // namespace silkworm::rlp

#endif  // SILKWORM_RLP_ENCODE_H_
