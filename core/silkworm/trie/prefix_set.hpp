/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_TRIE_PREFIX_SET_HPP_
#define SILKWORM_TRIE_PREFIX_SET_HPP_

#include <vector>

#include <silkworm/common/base.hpp>

namespace silkworm::trie {

/// A set of byte strings with the following property:
/// If x ∈ S and x starts with y, then y ∈ S.
/// Corresponds to RetainList in Erigon.
class PrefixSet {
  public:
    // copyable
    PrefixSet(const PrefixSet& other) = default;
    PrefixSet& operator=(const PrefixSet& other) = default;

  private:
    std::vector<Bytes> s_;
};

}  // namespace silkworm::trie

#endif  // SILKWORM_TRIE_PREFIX_SET_HPP_
