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

#include "change.hpp"

#include <algorithm>
#include <boost/endian/conversion.hpp>
#include <boost/iterator/counting_iterator.hpp>
#include <cstring>
#include <tuple>

#include "common/decoding_error.hpp"
#include "common/util.hpp"

namespace {
using namespace silkworm;

constexpr uint32_t key_len{kAddressLength};

std::tuple<uint32_t, uint32_t, uint32_t> decode_account_len(std::string_view b) {
  using boost::endian::load_big_u32;

  if (b.length() < 4) throw DecodingError("input too short");

  const uint32_t n{load_big_u32(byte_ptr_cast(b.data()))};

  const uint32_t val_offset{4 + n * key_len + 4 * n};
  if (b.length() < val_offset) throw DecodingError("input too short");

  const uint32_t total_val_len{load_big_u32(byte_ptr_cast(&b[val_offset - 4]))};
  if (b.length() < val_offset + total_val_len) throw DecodingError("input too short");

  return {n, val_offset, total_val_len};
}

std::string_view key_elem(std::string_view b, uint32_t i) {
  return b.substr(4 + i * key_len, key_len);
};

std::pair<uint32_t, uint32_t> indices(std::string_view lengths, uint32_t i) {
  using boost::endian::load_big_u32;

  uint32_t idx0{0};
  if (i > 0) idx0 = load_big_u32(byte_ptr_cast(&lengths[4 * (i - 1)]));
  uint32_t idx1 = load_big_u32(byte_ptr_cast(&lengths[4 * i]));

  return {idx0, idx1};
}
}  // namespace

namespace silkworm::db {

AccountChanges decode_account_changes(std::string_view b) {
  if (b.empty()) return {};

  auto [n, val_offset, total_val_len]{decode_account_len(b)};
  std::string_view lengths{b.substr(4 + n * key_len)};

  AccountChanges changes;
  for (uint32_t i{0}; i < n; ++i) {
    evmc::address key;
    std::memcpy(key.bytes, &b[4 + i * key_len], key_len);
    auto [idx0, idx1]{indices(lengths, i)};
    changes[key] = b.substr(val_offset + idx0, idx1 - idx0);
  }
  return changes;
}

namespace change {
std::optional<std::string_view> find_account(std::string_view b, std::string_view key) {
  assert(key.length() == key_len);

  if (b.empty()) return {};

  auto [n, val_offset, total_val_len]{decode_account_len(b)};

  uint32_t i{*std::lower_bound(
      boost::counting_iterator<uint32_t>(0), boost::counting_iterator<uint32_t>(n), key,
      [b](uint32_t i, std::string_view key) { return key_elem(b, i) < key; })};

  if (i >= n || key_elem(b, i) != key) return {};

  auto [idx0, idx1]{indices(b.substr(4 + n * key_len), i)};

  return b.substr(val_offset + idx0, idx1 - idx0);
}
}  // namespace change
}  // namespace silkworm::db
