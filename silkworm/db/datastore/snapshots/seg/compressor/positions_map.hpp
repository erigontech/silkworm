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

#include <cstddef>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace silkworm::snapshots::seg {

class PositionsMap {
  public:
    void update_with_word(
        size_t raw_word_length,
        const std::vector<std::pair<size_t, size_t>>& pattern_positions);

    std::vector<uint64_t> list_positions();
    std::vector<uint64_t> list_uses();

    static size_t position(size_t pattern_position, size_t prev_pattern_position);
    static size_t word_length_position(size_t word_length);
    static constexpr size_t kTerminatorPosition = 0;

  private:
    std::map<size_t, uint64_t> uses_;
};

}  // namespace silkworm::snapshots::seg
