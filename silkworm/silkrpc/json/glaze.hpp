
/*
   Copyright 2023 The Silkworm Authors

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <glaze/glaze.hpp>
#pragma GCC diagnostic pop

namespace silkworm::rpc {

inline constexpr std::string_view jsonVersion{"2.0"};
inline constexpr auto jsonVersionSize = 8;
inline constexpr auto addressSize = 64;
inline constexpr auto hashSize = 128;
inline constexpr auto bloomSize = 1024;
inline constexpr auto int64Size = 32;
inline constexpr auto dataSize = 4096;
inline constexpr auto ethCallResultFixedSize = 2048;

}  // namespace silkworm::rpc
