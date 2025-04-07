// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
        const std::function<uint64_t(void*)>& pattern_score_getter);
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
