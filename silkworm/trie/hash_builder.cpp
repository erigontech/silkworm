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
HashBuilder::HashBuilder(ByteView key0, ByteView value0)
    : key_{unpack_nibbles(key0)}, value_{value0} {}

void HashBuilder::add(ByteView packed, ByteView value) {
  Bytes key{unpack_nibbles(packed)};
  assert(key > key_);
  gen_struct_step(key_, key, value_);
  key_ = key;
  value_ = value;
}

evmc::bytes32 HashBuilder::root_hash() {
  gen_struct_step(key_, {}, value_);
  key_.clear();
  value_.clear();

  Bytes& node_ref{stack_.back()};
  evmc::bytes32 res{};
  if (node_ref.length() == kHashLength) {
    std::memcpy(res.bytes, node_ref.data(), kHashLength);
  } else {
    ethash::hash256 hash{ethash::keccak256(node_ref.data(), node_ref.length())};
    std::memcpy(res.bytes, hash.bytes, kHashLength);
  }
  return res;
}

// https://github.com/ledgerwatch/turbo-geth/blob/master/docs/programmers_guide/guide.md#generating-the-structural-information-from-the-sequence-of-keys
void HashBuilder::gen_struct_step(ByteView curr, const ByteView succ, const ByteView value) {
  for (bool build_extensions{false};; build_extensions = true) {
    const bool prec_exists{!groups_.empty()};
    const size_t prec_len{groups_.empty() ? 0 : groups_.size() - 1};
    const size_t succ_len{prefix_length(succ, curr)};
    const size_t max_len{std::max(prec_len, succ_len)};
    assert(max_len < curr.length());

    // Add the digit immediately following the max common prefix and compute length of remainder
    // length
    const uint8_t extra_digit{curr[max_len]};
    if (groups_.size() <= max_len) {
      groups_.resize(max_len + 1);
    }
    groups_[max_len] |= 1u << extra_digit;

    size_t remainder_start{max_len};
    if (!succ.empty() || prec_exists) {
      ++remainder_start;
    }

    const ByteView short_node_key{curr.substr(remainder_start)};
    if (!build_extensions) {
      stack_.emplace_back(node_ref(leaf_node_rlp(short_node_key, value)));
    } else {
      stack_.back() = node_ref(extension_node_rlp(short_node_key, stack_.back()));
    }

    // Check for the optional part
    if (prec_len <= succ_len && !succ.empty()) {
      return;
    }

    // Close the immediately encompassing prefix group, if needed
    if (!succ.empty() || prec_exists) {
      branch_ref(groups_[max_len]);
    }

    groups_.resize(max_len);

    // Check the end of recursion
    if (prec_len == 0) {
      return;
    }

    // Identify preceding key for the buildExtensions invocation
    curr = curr.substr(0, prec_len);
    while (!groups_.empty() && groups_.back() == 0) {
      groups_.pop_back();
    }
  }
}

// Takes children from the stack and replaces them with branch node ref.
void HashBuilder::branch_ref(uint16_t mask) {
  const size_t first_child_idx{stack_.size() - popcount(mask)};

  rlp::Header h;
  h.list = true;
  h.payload_length = 17;

  for (size_t i{first_child_idx}, digit{0}; digit < 16; ++digit) {
    if (mask & (1u << digit)) {
      h.payload_length += stack_[i++].length();
    }
  }

  Bytes rlp{};
  rlp::encode_header(rlp, h);

  for (size_t i{first_child_idx}, digit{0}; digit < 16; ++digit) {
    if (mask & (1u << digit)) {
      rlp::encode(rlp, stack_[i++]);
    } else {
      rlp.push_back(rlp::kEmptyStringCode);
    }
  }

  // branch nodes with values are not supported
  rlp.push_back(rlp::kEmptyStringCode);

  stack_.resize(first_child_idx + 1);
  stack_.back() = node_ref(rlp);
}
}  // namespace silkworm::trie
