/*
   Copyright 2022 The Silkworm Authors

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

#include <string>
#include <string_view>

#include <silkworm/core/common/base.hpp>

namespace silkworm::snappy {

// Snappy is a compression/decompression library. It does not aim for maximum compression, or compatibility
// with any other compression library; instead, it aims for very high speeds and reasonable compression.
// Snappy can be used in one of two modes: block format and framing (a.k.a. stream) format

// Snappy block format description: https://github.com/google/snappy/blob/main/format_description.txt

bool is_valid_compressed_data(ByteView data);

std::string compress(std::string_view data);

std::string decompress(std::string_view data);

Bytes compress(ByteView data);

Bytes decompress(ByteView data);

}  // namespace silkworm::snappy
