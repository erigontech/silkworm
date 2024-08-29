/*
   Copyright 2024 The Silkworm Authors

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

#pragma once

#include <memory>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots::seg {

class PatriciaTreeImpl;
class PatriciaTreeMatchFinder;
class PatriciaTreeMatchFinderImpl;

//! Patricia tree for an efficient search of substrings in a list of patterns.
class PatriciaTree {
  public:
    PatriciaTree();
    ~PatriciaTree();

    void insert(ByteView key, void* value);
    void* get(ByteView key);

  private:
    std::unique_ptr<PatriciaTreeImpl> p_impl_;
    friend PatriciaTreeMatchFinder;
};

class PatriciaTreeMatchFinder {
  public:
    struct Match {
        void* value{};
        size_t start{};
        size_t end{};
    };

    explicit PatriciaTreeMatchFinder(const PatriciaTree& tree);
    ~PatriciaTreeMatchFinder();

    //! Takes a word and returns a list of patterns that have a common prefix with the word.
    const std::vector<Match>& find_longest_matches(ByteView data);

  private:
    std::unique_ptr<PatriciaTreeMatchFinderImpl> p_impl_;
};

}  // namespace silkworm::snapshots::seg
