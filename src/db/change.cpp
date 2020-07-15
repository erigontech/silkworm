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

constexpr uint64_t kDefaultIncarnation{1};

// size_t -> uint32_t
constexpr uint32_t kAddressLen{kAddressLength};
constexpr uint32_t kHashLen{kHashLength};

std::tuple<uint32_t, uint32_t> decode_account_meta(std::string_view b) {
  using boost::endian::load_big_u32;

  if (b.length() < 4) throw DecodingError("input too short");

  uint32_t n{load_big_u32(byte_ptr_cast(&b[0]))};

  uint32_t val_pos{4 + n * kAddressLen + 4 * n};
  if (b.length() < val_pos) throw DecodingError("input too short");

  uint32_t total_val_len{load_big_u32(byte_ptr_cast(&b[val_pos - 4]))};
  if (b.length() < val_pos + total_val_len) throw DecodingError("input too short");

  return {n, val_pos};
}

std::tuple<uint32_t, uint32_t, uint32_t, uint32_t, uint32_t> decode_storage_meta(
    std::string_view b) {
  using boost::endian::load_big_u32;

  if (b.length() < 4) throw DecodingError("input too short");

  uint32_t num_of_contracts{load_big_u32(byte_ptr_cast(&b[0]))};
  uint32_t pos{num_of_contracts * (kAddressLen + 4)};
  uint32_t num_of_entries{load_big_u32(byte_ptr_cast(&b[pos]))};
  pos += 4;
  uint32_t num_of_non_default_incarnations{load_big_u32(byte_ptr_cast(&b[pos]))};
  uint32_t incarnation_pos{pos + 4};
  uint32_t key_pos{incarnation_pos + num_of_non_default_incarnations * 12};
  uint32_t val_pos{key_pos + num_of_entries * kHashLen};

  return {num_of_contracts, num_of_non_default_incarnations, incarnation_pos, key_pos, val_pos};
}

std::string_view account_address(std::string_view b, uint32_t i) {
  return b.substr(4 + i * kAddressLen, kAddressLen);
};

std::string_view storage_address(std::string_view b, uint32_t i) {
  return b.substr(4 + i * (4 + kAddressLen), kAddressLen);
};

std::pair<uint32_t, uint32_t> account_indices(std::string_view lengths, uint32_t i) {
  using boost::endian::load_big_u32;

  uint32_t idx0{0};
  if (i > 0) idx0 = load_big_u32(byte_ptr_cast(&lengths[4 * (i - 1)]));
  uint32_t idx1 = load_big_u32(byte_ptr_cast(&lengths[4 * i]));

  return {idx0, idx1};
}

std::string_view find_value(std::string_view b, uint32_t i) {
  using boost::endian::load_big_u16;
  using boost::endian::load_big_u32;

  uint32_t num_of_uint8{load_big_u32(byte_ptr_cast(&b[0]))};
  uint32_t num_of_uint16{load_big_u32(byte_ptr_cast(&b[4]))};
  uint32_t num_of_uint32{load_big_u32(byte_ptr_cast(&b[8]))};
  b = b.substr(12);
  uint32_t val_pos{num_of_uint8 + num_of_uint16 * 2 + num_of_uint32 * 4};

  auto val_index{[=](uint32_t i) -> uint32_t {
    if (i < num_of_uint8) {
      return static_cast<uint8_t>(b[i]);
    } else if (i < num_of_uint8 + num_of_uint16) {
      uint32_t pos{num_of_uint8 + (i - num_of_uint8) * 2};
      return load_big_u16(byte_ptr_cast(&b[pos]));
    } else {
      uint32_t pos{num_of_uint8 + num_of_uint16 * 2 + (i - num_of_uint8 - num_of_uint16) * 4};
      return load_big_u32(byte_ptr_cast(&b[pos]));
    }
  }};

  uint32_t start{i > 0 ? val_index(i - 1) : 0};
  uint32_t end{val_index(i)};

  return b.substr(val_pos + start, end - start);
}
}  // namespace

namespace silkworm::db {

AccountChanges AccountChanges::decode(std::string_view b) {
  if (b.empty()) return {};

  auto [n, val_pos]{decode_account_meta(b)};
  std::string_view lengths{b.substr(4 + n * kAddressLen)};

  AccountChanges changes;
  for (uint32_t i{0}; i < n; ++i) {
    evmc::address key;
    std::memcpy(key.bytes, &b[4 + i * kAddressLen], kAddressLen);
    auto [idx0, idx1]{account_indices(lengths, i)};
    changes[key] = b.substr(val_pos + idx0, idx1 - idx0);
  }
  return changes;
}

std::optional<std::string_view> AccountChanges::find(std::string_view b, std::string_view key) {
  using CI = boost::counting_iterator<uint32_t>;

  assert(key.length() == kAddressLen);

  if (b.empty()) return {};

  auto [n, val_pos]{decode_account_meta(b)};

  uint32_t i{*std::lower_bound(CI(0), CI(n), key, [b](uint32_t i, std::string_view address) {
    return account_address(b, i) < address;
  })};

  if (i >= n || account_address(b, i) != key) return {};

  auto [idx0, idx1]{account_indices(b.substr(4 + n * kAddressLen), i)};

  return b.substr(val_pos + idx0, idx1 - idx0);
}

std::optional<std::string_view> StorageChanges::find(std::string_view b,
                                                     std::string_view composite_key) {
  using CI = boost::counting_iterator<uint32_t>;
  using boost::endian::load_big_u32;
  using boost::endian::load_big_u64;

  assert(composite_key.length() == kAddressLength + kIncarnationLength + kHashLength);

  if (b.empty()) return {};

  std::string_view address{composite_key.substr(0, kAddressLength)};
  uint64_t incarnation{~load_big_u64(byte_ptr_cast(&composite_key[kAddressLength]))};
  std::string_view key{composite_key.substr(kAddressLength + kIncarnationLength)};

  auto [num_of_contracts, num_of_non_default_incarnations, incarnation_pos, key_pos,
        val_pos]{decode_storage_meta(b)};

  uint32_t contract_idx{*std::lower_bound(
      CI(0), CI(num_of_contracts), address,
      [b](uint32_t i, std::string_view address) { return storage_address(b, i) < address; })};

  if (contract_idx >= num_of_contracts || storage_address(b, contract_idx) != address) return {};

  if (incarnation > 0) {
    uint64_t found_incarnation{kDefaultIncarnation};

    std::string_view inc_view{b.substr(incarnation_pos)};
    auto incarnation_contract_idx{
        [inc_view](uint32_t i) { return load_big_u32(byte_ptr_cast(&inc_view[12 * i])); }};

    uint32_t incarnation_idx{*std::lower_bound(CI(0), CI(num_of_non_default_incarnations),
                                               contract_idx,
                                               [&](uint32_t i, uint32_t contract_idx) {
                                                 return incarnation_contract_idx(i) < contract_idx;
                                               })};

    if (incarnation_idx < num_of_non_default_incarnations &&
        incarnation_contract_idx(incarnation_idx) == contract_idx) {
      found_incarnation = ~load_big_u64(byte_ptr_cast(&inc_view[12 * incarnation_idx + 4]));
    }

    if (found_incarnation != incarnation) return {};
  }

  uint32_t from{0};
  if (contract_idx > 0) {
    from = load_big_u32(byte_ptr_cast(&b[contract_idx * (kAddressLen + 4)]));
  }
  uint32_t to{load_big_u32(byte_ptr_cast(&b[(contract_idx + 1) * (kAddressLen + 4)]))};

  std::string_view key_view{b.substr(key_pos)};
  uint32_t key_idx{
      *std::lower_bound(CI(from), CI(to), key, [key_view](uint32_t i, std::string_view key) {
        return key_view.substr(i * kHashLen, kHashLen) < key;
      })};
  if (key_idx == to || key_view.substr(key_idx * kHashLen, kHashLen) != key) return {};

  return find_value(b.substr(val_pos), key_idx);
}
}  // namespace silkworm::db
