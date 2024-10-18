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

#include <cstdint>

#include "../common/util/bitmask_operators.hpp"

namespace silkworm::snapshots::seg {

enum class CompressionKind : uint8_t {
    kNone = 0b0,
    kKeys = 0b1,
    kValues = 0b10,
    kAll = 0b11,
};

consteval void enable_bitmask_operator_and(CompressionKind);
consteval void enable_bitmask_operator_or(CompressionKind);
consteval void enable_bitmask_operator_not(CompressionKind);

}  // namespace silkworm::snapshots::seg
