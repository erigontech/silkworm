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

#include "change_set.hpp"

#include <boost/endian/conversion.hpp>
#include <cstring>

#include "common/util.hpp"
#include "rlp/decode.hpp"

namespace silkworm {

AccountChanges decode_account_changes(std::string_view b) {
  using boost::endian::load_big_u32;

  if (b.empty()) return {};
  if (b.length() < 4) throw rlp::DecodingError("input too short");

  const uint32_t n{load_big_u32(byte_ptr_cast(b.data()))};
  const uint32_t key_len{kAddressLength};

  const uint32_t val_offset{4 + n * key_len + 4 * n};
  if (b.length() < val_offset) throw rlp::DecodingError("input too short");

  const uint32_t total_val_len{load_big_u32(byte_ptr_cast(&b[val_offset - 4]))};
  if (b.length() < val_offset + total_val_len) throw rlp::DecodingError("input too short");

  AccountChanges changes;
  for (uint32_t i = 0; i < n; ++i) {
    evmc::address key;
    std::memcpy(key.bytes, &b[4 + i * key_len], key_len);
    uint32_t idx0{0};
    if (i > 0) {
      idx0 = load_big_u32(byte_ptr_cast(&b[n * key_len + 4 * i]));
    }
    uint32_t idx1 = load_big_u32(byte_ptr_cast(&b[4 + n * key_len + 4 * i]));
    changes[key] = b.substr(val_offset + idx0, idx1 - idx0);
  }
  return changes;
}
}  // namespace silkworm
