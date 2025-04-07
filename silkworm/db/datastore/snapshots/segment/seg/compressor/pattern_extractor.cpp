// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "pattern_extractor.hpp"

#include <sais.h>

#include <algorithm>
#include <span>
#include <stdexcept>

#include <silkworm/core/common/base.hpp>

#include "lcp_kasai.hpp"

namespace silkworm::snapshots::seg {

//! How large one superstring gets before processed.
static constexpr size_t kSuperstringLimit = 16_Mebi;

//! Minimum pattern length.
static constexpr size_t kPatternLenMin = 5;

//! Maximum pattern length.
static constexpr size_t kPatternLenMax = 128;

//! Minimum score of a pattern in a word.
static constexpr uint64_t kPatternScoreMin = 1024;

Superstring::Superstring() {
    superstring_.reserve(kSuperstringLimit);
}

bool Superstring::can_add_word(ByteView word) {
    size_t extra_size = word.size() * 2 + 2;
    return superstring_.size() + extra_size <= kSuperstringLimit;
}

void Superstring::add_word(ByteView word, bool skip_copy) {
    size_t start = superstring_.size();
    superstring_.append(word.size() * 2 + 2, 0);
    if (skip_copy) return;
    for (size_t i = 0, s = start; i < word.size(); ++i, s += 2) {
        superstring_[s] = 1;
        superstring_[s + 1] = word[i];
    }
}

void Superstring::substr(Bytes& out, size_t pos, size_t count) const {
    out.resize(count);
    size_t offset = pos * 2;
    for (size_t i = 0, s = 1; i < count; ++i, s += 2) {
        out[i] = superstring_[offset + s];
    }
}

PatternExtractor::PatternExtractor(std::optional<size_t> pattern_score_min)
    : pattern_score_min_(pattern_score_min.value_or(kPatternScoreMin)) {
    pattern_.reserve(kPatternLenMax);
}

void PatternExtractor::extract_patterns(const Superstring& superstring, absl::FunctionRef<void(ByteView, uint64_t)> collector) {
    if (superstring.size() == 0)
        return;

    auto& lcp = lcp_;
    auto& sa = sa_;
    auto& inv = inv_;

    // Build suffix array
    sa.resize(superstring.size());
    if (sais(superstring.data(), sa.data(), static_cast<int>(superstring.size())) != 0) {
        throw std::runtime_error("PatternExtractor::extract_patterns: sais algorithm failed");
    }

    // Filter out suffixes that start with odd positions
    size_t n = sa.size() / 2;
    std::span<int> filtered(sa.data(), n);
    size_t j = 0;
    for (int i : sa) {
        if ((i & 1) == 0) {
            filtered[j++] = i >> 1;
        }
    }

    // Create an inverted array
    inv.resize(n);
    for (size_t i = 0; i < n; ++i) {
        inv[static_cast<size_t>(filtered[i])] = static_cast<int>(i);
    }

    lcp.resize(n);
    lcp_kasai(superstring, filtered.data(), inv.data(), lcp.data(), static_cast<int>(n));

    // Walk over LCP array and compute the scores of the strings
    auto& b = inv;
    j = 0;
    for (size_t i = 0; i < n - 1; ++i) {
        if (lcp[i + 1] >= lcp[i]) {
            j = i;
            continue;
        }

        bool prev_skipped = false;
        for (int l = lcp[i]; (l > lcp[i + 1]) && (l >= static_cast<int>(kPatternLenMin)); --l) {
            if ((l > static_cast<int>(kPatternLenMax)) || ((l > 20) && (l & (l - 1)))) {  // is power of 2
                prev_skipped = true;
                continue;
            }

            bool is_new = false;
            while ((j > 0) && (lcp[j - 1] >= l)) {
                --j;
                is_new = true;
            }

            if (!is_new && !prev_skipped) {
                break;
            }

            size_t window = i - j + 2;
            std::copy_n(&filtered[j], window, b.begin());
            std::ranges::sort(std::span<int>(b.data(), window));

            size_t repeats = 1;
            size_t last_k = 0;
            for (size_t k = 1; k < window; ++k) {
                if (b[k] >= b[last_k] + l) {
                    ++repeats;
                    last_k = k;
                }
            }

            if (((l < 8) || (l > 64)) && (repeats < pattern_score_min_)) {
                prev_skipped = true;
                continue;
            }

            uint64_t score = repeats * static_cast<size_t>(l);
            if (score < pattern_score_min_) {
                prev_skipped = true;
                continue;
            }

            superstring.substr(pattern_, static_cast<size_t>(filtered[i]), static_cast<size_t>(l));
            collector(pattern_, score);

            prev_skipped = false;
            break;
        }
    }
}

}  // namespace silkworm::snapshots::seg
