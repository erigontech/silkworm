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

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>

#include "block_id.hpp"
#include "hash.hpp"

namespace silkworm {

struct ChainHead {
    BlockNum height{0};
    Hash hash;
    intx::uint256 total_difficulty;

    friend bool operator==(const ChainHead&, const ChainHead&) = default;
};

inline bool operator==(const ChainHead& a, const BlockId& b) {
    return a.height == b.number && a.hash == b.hash;
}

inline bool operator==(const BlockId& a, const ChainHead& b) {
    return a.number == b.height && a.hash == b.hash;
}

inline BlockId to_BlockId(const ChainHead& head) {
    return {.number = head.height, .hash = head.hash};
}

}  // namespace silkworm
