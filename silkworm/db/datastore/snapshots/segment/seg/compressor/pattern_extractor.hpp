// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <vector>

#include <absl/functional/function_ref.h>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots::seg {

/**
 * Superstring - a chunk of data that is built from the raw data and acts as an input for the pattern extraction phase.
 * Input words are augmented in pairs of bytes with 1-s and terminated with (0,0) like so: (1,b1),(1,b2)...(1,bN),(0,0).
 */
class Superstring {
  public:
    Superstring();
    explicit Superstring(Bytes superstring) : superstring_(std::move(superstring)) {}

    bool can_add_word(ByteView word);
    void add_word(ByteView word, bool skip_copy = false);
    void substr(Bytes& out, size_t pos, size_t count) const;

    const uint8_t* data() const { return superstring_.data(); }
    size_t size() const { return superstring_.size(); }
    void clear() { superstring_.clear(); }

    bool has_same_chars(int i1, int j1) const {
        auto i = static_cast<size_t>(i1);
        auto j = static_cast<size_t>(j1);
        return superstring_[i * 2] && superstring_[j * 2] && (superstring_[i * 2 + 1] == superstring_[j * 2 + 1]);
    }

  private:
    Bytes superstring_;
};

class PatternExtractor {
  public:
    explicit PatternExtractor(std::optional<size_t> pattern_score_min = std::nullopt);

    /**
     * \brief Extract patterns from a superstring.
     * \param superstring
     * \param collector Callback accepting a pattern string and its score.
     */
    void extract_patterns(const Superstring& superstring, absl::FunctionRef<void(ByteView, uint64_t)> collector);

  private:
    size_t pattern_score_min_;
    Bytes pattern_;
    std::vector<int> lcp_, sa_, inv_;
};

}  // namespace silkworm::snapshots::seg
