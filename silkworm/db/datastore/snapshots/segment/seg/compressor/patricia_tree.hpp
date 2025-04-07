// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
