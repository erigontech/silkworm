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

#include "hash_builder.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <ethash/keccak.hpp>
#include <iterator>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm::trie {

static Bytes unpack_nibbles(ByteView packed) {
  Bytes out(2 * packed.length(), '\0');
  for (size_t i{0}; i < packed.length(); ++i) {
    out[2 * i] = packed[i] >> 4;
    out[2 * i + 1] = packed[i] & 0xF;
  }
  return out;
}

static Bytes encode_path(ByteView path, bool terminating) {
  Bytes res(path.length() / 2 + 1, '\0');
  bool odd{path.length() % 2 != 0};

  if (!terminating && !odd) {
    res[0] = 0x00;
  } else if (!terminating && odd) {
    res[0] = 0x10;
  } else if (terminating && !odd) {
    res[0] = 0x20;
  } else if (terminating && odd) {
    res[0] = 0x30;
  }

  if (odd) {
    res[0] |= path[0];
    for (size_t i{1}; i < res.length(); ++i) {
      res[i] = (path[2 * i - 1] << 4) + path[2 * i];
    }
  } else {
    for (size_t i{1}; i < res.length(); ++i) {
      res[i] = (path[2 * i - 2] << 4) + path[2 * i - 1];
    }
  }

  return res;
}

// RLP of a leaf or extension node
static Bytes short_node_rlp(ByteView encoded_path, ByteView payload) {
  Bytes rlp{};
  rlp::Header h;
  h.list = true;
  h.payload_length = rlp::length(encoded_path) + rlp::length(payload);
  rlp::encode_header(rlp, h);
  rlp::encode(rlp, encoded_path);
  rlp::encode(rlp, payload);
  return rlp;
}

static ByteView node_ref(ByteView rlp) {
  if (rlp.length() < kHashLength) {
    return rlp;
  }

  ethash::hash256 hash{ethash::keccak256(rlp.data(), rlp.length())};
  return {hash.bytes, kHashLength};
}

HashBuilder::HashBuilder(ByteView key0, ByteView val0)
    : path_{unpack_nibbles(key0)}, value_{val0} {}

void HashBuilder::add(ByteView packed, ByteView val) {
  Bytes key{unpack_nibbles(packed)};
  assert(key > path_);

  size_t len{std::min(key.length(), path_.length())};
  size_t matching_bytes = std::distance(
      key.begin(), std::mismatch(key.begin(), key.begin() + len, path_.begin()).first);

  if (matching_bytes == len) {  // full match
    // insert the nibble into the branch
    uint8_t nibble{key[len]};
    branch_mask_ |= 1u << nibble;

    // and the child
    Bytes leaf_path{encode_path(key.substr(len + 1), /*terminating=*/true)};
    children_[nibble] = node_ref(short_node_rlp(leaf_path, val));
  } else {  // new branch
    // TODO[Byzantium] implement branching
  }
}

evmc::bytes32 HashBuilder::root_hash() {
  Bytes rlp;
  if (popcount(branch_mask_) == 0) {
    // leaf node
    rlp = short_node_rlp(encode_path(path_, /*terminating=*/true), value_);
  } else if (path_.empty()) {
    // branch node
    rlp = branch_node_rlp();
  } else {
    // extension node
    rlp = short_node_rlp(encode_path(path_, /*terminating=*/false), node_ref(branch_node_rlp()));
  }

  ethash::hash256 hash{ethash::keccak256(rlp.data(), rlp.length())};
  evmc::bytes32 res{};
  std::memcpy(res.bytes, hash.bytes, kHashLength);
  return res;
}

Bytes HashBuilder::branch_node_rlp() const {
  Bytes rlp{};
  rlp::Header h;
  h.list = true;
  h.payload_length = 16;
  for (int i{0}; i < 16; ++i) {
    if (branch_mask_ & (1u << i)) {
      h.payload_length += children_[i].length();
    }
  }
  h.payload_length += rlp::length(value_);
  rlp::encode_header(rlp, h);
  for (int i{0}; i < 16; ++i) {
    if (branch_mask_ & (1u << i)) {
      rlp::encode(rlp, children_[i]);
    } else {
      rlp.push_back(rlp::kEmptyStringCode);
    }
  }
  rlp::encode(rlp, value_);
  return rlp;
}
}  // namespace silkworm::trie
