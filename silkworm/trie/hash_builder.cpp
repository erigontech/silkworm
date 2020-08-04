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

#include <cstring>
#include <ethash/keccak.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm::trie {

HashBuilder::HashBuilder(ByteView key0, ByteView val0) : path_{key0}, value_{val0} {}

void HashBuilder::add(ByteView, ByteView) {
  // TODO(Andrew) implement
}

evmc::bytes32 HashBuilder::root_hash() {
  thread_local Bytes rlp;
  thread_local ethash::hash256 hash;

  evmc::bytes32 res{};

  rlp.clear();

  if (popcount(branch_mask_) == 0) {
    Bytes path{encoded_path(/*terminating=*/true)};
    rlp::Header h{.list = true, .payload_length = rlp::length(path)};
    h.payload_length += rlp::length(value_);
    rlp::encode_header(rlp, h);
    rlp::encode(rlp, path);
    rlp::encode(rlp, value_);

    hash = ethash::keccak256(rlp.data(), rlp.length());
    std::memcpy(res.bytes, hash.bytes, kHashLength);
    return res;
  } else {
    // TODO(Andrew) implement
    return res;
  }
}

Bytes HashBuilder::encoded_path(bool terminating) const {
  if (odd_) {
    Bytes res(path_.length(), '\0');
    res[0] = terminating ? 0x30 : 0x10;
    res[0] |= path_[0] >> 4;
    for (size_t i{1}; i < path_.length(); ++i) {
      res[i] = (path_[i - 1] << 4) + (path_[i] >> 4);
    }
    return res;
  } else {
    Bytes res(path_.length() + 1, '\0');
    if (terminating) {
      res[0] = 0x20;
    }
    std::memcpy(&res[1], &path_[0], path_.length());
    return res;
  }
}
}  // namespace silkworm::trie
