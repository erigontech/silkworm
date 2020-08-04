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

static Bytes encode_path(ByteView path, bool odd, bool terminating, bool skip_first_nibble) {
  if (odd || skip_first_nibble) {
    assert(!path.empty());
  }

  size_t len{path.length()};
  if (!odd && !skip_first_nibble) {
    ++len;
  }
  Bytes res(len, '\0');

  if (!terminating && !odd) {
    res[0] = 0x00;
  } else if (!terminating && odd) {
    res[0] = 0x10;
  } else if (terminating && !odd) {
    res[0] = 0x20;
  } else if (terminating && odd) {
    res[0] = 0x30;
  }

  if (odd && skip_first_nibble) {
    res[0] |= path[0] & 0xf;
    std::memcpy(&res[1], &path[1], len - 1);
  } else if (!odd && !skip_first_nibble) {
    std::memcpy(&res[1], &path[0], len - 1);
  } else {
    if (!skip_first_nibble) {
      res[0] |= path[0] >> 4;
    }
    for (size_t i{1}; i < path.length(); ++i) {
      res[i] = (path[i - 1] << 4) + (path[i] >> 4);
    }
  }

  return res;
}

// RLP of a leaf or extension node
static Bytes short_node_rlp(ByteView encoded_path, ByteView payload) {
  thread_local Bytes rlp;
  rlp.clear();
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

  thread_local ethash::hash256 hash;
  hash = ethash::keccak256(rlp.data(), rlp.length());
  return {hash.bytes, kHashLength};
}

HashBuilder::HashBuilder(ByteView key0, ByteView val0) : path_{key0}, value_{val0} {}

void HashBuilder::add(ByteView key, ByteView val) {
  assert(key > path_);

  size_t len{std::min(key.length(), path_.length())};
  size_t matching_bytes = std::distance(
      key.begin(), std::mismatch(key.begin(), key.begin() + len, path_.begin()).first);

  if (matching_bytes == path_.length() && !odd_ && key.length() > path_.length()) {
    // insert the key into the branch
    key = key.substr(path_.length());
    unsigned nibble{static_cast<unsigned>(key[0]) >> 4};
    branch_mask_ |= 1u << nibble;

    // and the child
    Bytes leaf_path{
        encode_path(key, /*odd=*/true, /*terminating=*/true, /*skip_first_nibble=*/true)};
    children_[nibble] = node_ref(short_node_rlp(leaf_path, val));
  } else {
    // TODO[Byzantium] implement the rest
  }
}

evmc::bytes32 HashBuilder::root_hash() {
  Bytes rlp;
  if (popcount(branch_mask_) == 0) {
    // leaf node
    rlp = short_node_rlp(encoded_path(/*terminating=*/true), value_);
  } else if (path_.empty()) {
    // branch node
    rlp = branch_node_rlp();
  } else {
    // extension node
    rlp = short_node_rlp(encoded_path(/*terminating=*/false), node_ref(branch_node_rlp()));
  }

  thread_local ethash::hash256 hash;
  hash = ethash::keccak256(rlp.data(), rlp.length());
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

Bytes HashBuilder::encoded_path(bool terminating) const {
  return encode_path(path_, odd_, terminating, /*skip_first_nibble=*/false);
}
}  // namespace silkworm::trie
