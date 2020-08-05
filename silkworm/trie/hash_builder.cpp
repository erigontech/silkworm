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

static Bytes leaf_node_rlp(ByteView path, ByteView value) {
  return short_node_rlp(encode_path(path, /*terminating=*/true), value);
}

static Bytes extension_node_rlp(ByteView path, ByteView child_ref) {
  return short_node_rlp(encode_path(path, /*terminating=*/false), child_ref);
}

static ByteView node_ref(ByteView rlp) {
  if (rlp.length() < kHashLength) {
    return rlp;
  }

  thread_local ethash::hash256 hash;
  hash = ethash::keccak256(rlp.data(), rlp.length());
  return {hash.bytes, kHashLength};
}

HashBuilder::HashBuilder(ByteView key0, ByteView val0)
    : path_{unpack_nibbles(key0)}, value_{val0} {}

void HashBuilder::add(ByteView packed, ByteView val) {
  Bytes key{unpack_nibbles(packed)};
  assert(key > path_);

  size_t len{std::min(key.length(), path_.length())};
  size_t match = std::distance(key.begin(),
                               std::mismatch(key.begin(), key.begin() + len, path_.begin()).first);

  if (match == len) {
    // full match
    uint8_t nibble{key[len]};
    // TODO[Byzantium] nibble clash
    branch_mask_ |= 1u << nibble;
    children_[nibble] = leaf_node_rlp(ByteView{key}.substr(len + 1), val);
  } else {
    // new branch
    children_[path_[match]] = node_rlp(ByteView{path_}.substr(match + 1));
    children_[key[match]] = leaf_node_rlp(ByteView{key}.substr(match + 1), val);
    branch_mask_ = 0;
    branch_mask_ |= 1u << path_[match];
    branch_mask_ |= 1u << key[match];
    path_.resize(match);
    value_.clear();
  }
}

evmc::bytes32 HashBuilder::root_hash() const {
  Bytes rlp{node_rlp(path_)};
  ethash::hash256 hash{ethash::keccak256(rlp.data(), rlp.length())};
  evmc::bytes32 res{};
  std::memcpy(res.bytes, hash.bytes, kHashLength);
  return res;
}

Bytes HashBuilder::node_rlp(ByteView path) const {
  if (popcount(branch_mask_) == 0) {
    return leaf_node_rlp(path, value_);
  } else if (path.empty()) {
    return branch_node_rlp();
  } else {
    return extension_node_rlp(path, node_ref(branch_node_rlp()));
  }
}

Bytes HashBuilder::branch_node_rlp() const {
  Bytes rlp{};
  rlp::Header h;
  h.list = true;
  h.payload_length = 16;
  for (int i{0}; i < 16; ++i) {
    if (branch_mask_ & (1u << i)) {
      h.payload_length += std::min(children_[i].length(), kHashLength);
    }
  }
  h.payload_length += rlp::length(value_);
  rlp::encode_header(rlp, h);
  for (int i{0}; i < 16; ++i) {
    if (branch_mask_ & (1u << i)) {
      rlp::encode(rlp, node_ref(children_[i]));
    } else {
      rlp.push_back(rlp::kEmptyStringCode);
    }
  }
  rlp::encode(rlp, value_);
  return rlp;
}
}  // namespace silkworm::trie
