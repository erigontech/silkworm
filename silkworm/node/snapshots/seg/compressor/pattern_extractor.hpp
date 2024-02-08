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

#include <optional>
#include <vector>

#include <absl/functional/function_ref.h>

#include <silkworm/core/common/bytes.hpp>

#include "intx/intx.hpp"

namespace silkworm::snapshots::seg {

/**
 * Superstring - a chunk of data that is built from the raw data and acts as an input for the pattern extraction phase.
 * Input words are augmented in pairs of bytes with 1-s and terminated with (0,0) like so: (1,b1),(1,b2)...(1,bN),(0,0).
 */
class Superstring {
  public:
    Superstring();
    explicit Superstring(Bytes superstring) : superstring_(std::move(superstring)) {}

    void add_word(ByteView word);
    void substr(Bytes& out, size_t pos, size_t count) const;

    const uint8_t* data() const { return superstring_.data(); }
    size_t size() const { return superstring_.size(); }

    inline bool has_same_chars(int i1, int j1) const {
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
