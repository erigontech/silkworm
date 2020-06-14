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

#include "encode.hpp"

namespace silkworm::rlp {
void encode(std::ostream& to, uint64_t n) {
  if (n == 0) {
    to << '\x80';
  } else if (n < (1ull << 7)) {
    to << static_cast<char>(n);
  } else if (n < (1ull << 8)) {
    to << '\x81';
    to << static_cast<char>(n);
  } else if (n < (1ull << 16)) {
    to << '\x82';
    to << static_cast<char>(n >> 8);
    to << static_cast<char>(n);
  } else if (n < (1ull << 24)) {
    to << '\x83';
    to << static_cast<char>(n >> 16);
    to << static_cast<char>(n >> 8);
    to << static_cast<char>(n);
  } else if (n < (1ull << 32)) {
    to << '\x84';
    to << static_cast<char>(n >> 24);
    to << static_cast<char>(n >> 16);
    to << static_cast<char>(n >> 8);
    to << static_cast<char>(n);
  } else if (n < (1ull << 40)) {
    to << '\x85';
    to << static_cast<char>(n >> 32);
    to << static_cast<char>(n >> 24);
    to << static_cast<char>(n >> 16);
    to << static_cast<char>(n >> 8);
    to << static_cast<char>(n);
  } else if (n < (1ull << 48)) {
    to << '\x86';
    to << static_cast<char>(n >> 40);
    to << static_cast<char>(n >> 32);
    to << static_cast<char>(n >> 24);
    to << static_cast<char>(n >> 16);
    to << static_cast<char>(n >> 8);
    to << static_cast<char>(n);
  } else if (n < (1ull << 56)) {
    to << '\x87';
    to << static_cast<char>(n >> 48);
    to << static_cast<char>(n >> 40);
    to << static_cast<char>(n >> 32);
    to << static_cast<char>(n >> 24);
    to << static_cast<char>(n >> 16);
    to << static_cast<char>(n >> 8);
    to << static_cast<char>(n);
  } else {
    to << '\x88';
    to << static_cast<char>(n >> 56);
    to << static_cast<char>(n >> 48);
    to << static_cast<char>(n >> 40);
    to << static_cast<char>(n >> 32);
    to << static_cast<char>(n >> 24);
    to << static_cast<char>(n >> 16);
    to << static_cast<char>(n >> 8);
    to << static_cast<char>(n);
  }
}
}  // namespace silkworm::rlp
