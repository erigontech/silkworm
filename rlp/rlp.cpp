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

#include "rlp.hpp"

namespace silkworm::rlp {
void encode(std::ostream& s, uint64_t n) {
  if (n == 0) {
    s << '\x80';
  } else if (n < (1ull << 7)) {
    s << static_cast<char>(n);
  } else if (n < (1ull << 8)) {
    s << '\x81';
    s << static_cast<char>(n);
  } else if (n < (1ull << 16)) {
    s << '\x82';
    s << static_cast<char>(n >> 8);
    s << static_cast<char>(n);
  } else if (n < (1ull << 24)) {
    s << '\x83';
    s << static_cast<char>(n >> 16);
    s << static_cast<char>(n >> 8);
    s << static_cast<char>(n);
  } else if (n < (1ull << 32)) {
    s << '\x84';
    s << static_cast<char>(n >> 24);
    s << static_cast<char>(n >> 16);
    s << static_cast<char>(n >> 8);
    s << static_cast<char>(n);
  } else if (n < (1ull << 40)) {
    s << '\x85';
    s << static_cast<char>(n >> 32);
    s << static_cast<char>(n >> 24);
    s << static_cast<char>(n >> 16);
    s << static_cast<char>(n >> 8);
    s << static_cast<char>(n);
  } else if (n < (1ull << 48)) {
    s << '\x86';
    s << static_cast<char>(n >> 40);
    s << static_cast<char>(n >> 32);
    s << static_cast<char>(n >> 24);
    s << static_cast<char>(n >> 16);
    s << static_cast<char>(n >> 8);
    s << static_cast<char>(n);
  } else if (n < (1ull << 56)) {
    s << '\x87';
    s << static_cast<char>(n >> 48);
    s << static_cast<char>(n >> 40);
    s << static_cast<char>(n >> 32);
    s << static_cast<char>(n >> 24);
    s << static_cast<char>(n >> 16);
    s << static_cast<char>(n >> 8);
    s << static_cast<char>(n);
  } else {
    s << '\x88';
    s << static_cast<char>(n >> 56);
    s << static_cast<char>(n >> 48);
    s << static_cast<char>(n >> 40);
    s << static_cast<char>(n >> 32);
    s << static_cast<char>(n >> 24);
    s << static_cast<char>(n >> 16);
    s << static_cast<char>(n >> 8);
    s << static_cast<char>(n);
  }
}
}  // namespace silkworm::rlp
