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

#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

#include "patricia_tree.hpp"

namespace silkworm::snapshots::seg {

class PatternCoveringSearchImpl;

class PatternCoveringSearch {
  public:
    PatternCoveringSearch(
        const PatriciaTree& patterns_tree,
        std::function<uint64_t(void*)> pattern_score_getter);
    ~PatternCoveringSearch();

    struct Result {
        /**
         * Positions of patterns found in a word.
         * Patterns are represented by their corresponding values in the PatriciaTree.
         */
        std::vector<std::pair<size_t, void*>> pattern_positions;

        /**
         * Ranges in a word that were not covered by patterns.
         * Each range has a start and end index.
         */
        std::vector<std::pair<size_t, size_t>> uncovered_ranges;

        void clear();
    };

    /**
     * Find an optimal covering of a given word with patterns.
     * Ideally we want a covering that has maximal score and no intersections.
     */
    const Result& cover_word(ByteView word);

  private:
    std::unique_ptr<PatternCoveringSearchImpl> p_impl_;
};

}  // namespace silkworm::snapshots::seg
