// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "pattern_covering.hpp"

#include <cstdint>
#include <limits>

#include <boost/circular_buffer.hpp>

namespace silkworm::snapshots::seg {

//! A result of dynamic programming for a certain starting position.
struct PatternCoveringSearchDynamicCell {
    size_t optim_start{};
    size_t cover_start{};
    int compression{};
    uint64_t score{};
    size_t pattern_index{};
};

using DynamicCell = PatternCoveringSearchDynamicCell;
using Ring = boost::circular_buffer_space_optimized<DynamicCell>;
using Result = PatternCoveringSearch::Result;

class PatternCoveringSearchImpl {
  public:
    PatternCoveringSearchImpl(
        const PatriciaTree& patterns_tree,
        std::function<uint64_t(void*)> pattern_score_getter)
        : match_finder_(patterns_tree),
          pattern_score_getter_(std::move(pattern_score_getter)),
          cell_ring_(std::numeric_limits<size_t>::max()) {}

    const Result& cover_word(ByteView word);

  private:
    PatriciaTreeMatchFinder match_finder_;
    std::function<uint64_t(void*)> pattern_score_getter_;
    Ring cell_ring_;
    std::vector<size_t> pattern_indexes_;
    Result result_;
};

void Result::clear() {
    pattern_positions.clear();
    uncovered_ranges.clear();
}

const Result& PatternCoveringSearchImpl::cover_word(ByteView word) {
    result_.clear();

    auto& matches = match_finder_.find_longest_matches(word);
    if (matches.empty()) {
        result_.uncovered_ranges.emplace_back(0, word.size());
        return result_;
    }

    cell_ring_.clear();
    pattern_indexes_.clear();

    // This is a linked list of pattern matches indexes organized in pairs:
    // * each even element is a match index;
    // * each odd element is an index of the next entry within the list, or zero for a tail entry.
    // The list starts with a sentinel entry - [0, 0].
    auto& patterns = pattern_indexes_;
    patterns.push_back(0);
    patterns.push_back(0);

    const auto& last_match = matches.back();
    for (size_t i = last_match.start; i < last_match.end; ++i) {
        DynamicCell cell{
            .optim_start = i + 1,
            .cover_start = word.size(),
        };
        cell_ring_.push_back(cell);
    }

    // Starting from the last match
    for (size_t i = matches.size(); i > 0; --i) {
        const auto& match = matches[i - 1];
        uint64_t pattern_score = pattern_score_getter_(match.value);
        auto& first_cell = cell_ring_[0];
        int max_compression = first_cell.compression;
        uint64_t max_score = first_cell.score;
        DynamicCell max_cell = first_cell;
        bool max_include = false;

        for (size_t e = 0; e < cell_ring_.size(); ++e) {
            auto& cell = cell_ring_[e];
            int comp = cell.compression - 4;

            if (cell.cover_start >= match.end) {
                comp += static_cast<int>(match.end - match.start);
            } else {
                comp += static_cast<int>(cell.cover_start - match.start);
            }
            uint64_t score = cell.score + pattern_score;

            if ((comp > max_compression) || ((comp == max_compression) && (score > max_score))) {
                max_compression = comp;
                max_score = score;
                max_include = true;
                max_cell = cell;
            } else if (cell.optim_start > match.end) {
                cell_ring_.resize(e);
                break;
            }
        }

        DynamicCell cell{
            .optim_start = match.start,
            .compression = max_compression,
            .score = max_score,
        };

        if (max_include) {
            cell.cover_start = match.start;
            cell.pattern_index = patterns.size();

            patterns.push_back(i - 1);
            patterns.push_back(max_cell.pattern_index);
        } else {
            cell.cover_start = max_cell.cover_start;
            cell.pattern_index = max_cell.pattern_index;
        }

        cell_ring_.push_front(cell);
    }

    auto& optimal_cell = cell_ring_[0];
    size_t last_uncovered = 0;
    auto& uncovered = result_.uncovered_ranges;

    for (size_t pattern_index = optimal_cell.pattern_index; pattern_index != 0; pattern_index = patterns[pattern_index + 1]) {
        size_t match_index = patterns[pattern_index];
        auto& match = matches[match_index];

        if (match.start > last_uncovered) {
            uncovered.emplace_back(last_uncovered, match.start);
        }
        last_uncovered = match.end;

        result_.pattern_positions.emplace_back(match.start, match.value);
    }

    if (word.size() > last_uncovered) {
        uncovered.emplace_back(last_uncovered, word.size());
    }

    return result_;
}

PatternCoveringSearch::PatternCoveringSearch(
    const PatriciaTree& patterns_tree,
    const std::function<uint64_t(void*)>& pattern_score_getter)
    : p_impl_(std::make_unique<PatternCoveringSearchImpl>(patterns_tree, pattern_score_getter)) {}

PatternCoveringSearch::~PatternCoveringSearch() { static_assert(true); }

const Result& PatternCoveringSearch::cover_word(ByteView word) {
    return p_impl_->cover_word(word);
}

}  // namespace silkworm::snapshots::seg
