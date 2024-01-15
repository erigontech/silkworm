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

#include "writer.hpp"

#include <charconv>
#include <iostream>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc {

ChunkWriter::ChunkWriter(StreamWriter& writer) : writer_(writer) {}

Task<std::size_t> ChunkWriter::write(std::string_view content) {
    auto size = content.size();
    std::array<char, 19> str{};

    std::size_t written{0};
    if (auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), size, 16); ec == std::errc()) {
        auto view = std::string_view(str.data(), ptr);

        std::string chunk(view.size() + 2 * kChunkSep.size() + content.size(), '\0');
        chunk = view;
        chunk += kChunkSep;
        chunk += content;
        chunk += kChunkSep;
        written = co_await writer_.write(chunk);
    } else {
        SILK_ERROR << "Invalid conversion for size " << size;
    }

    co_return written;
}

Task<void> ChunkWriter::close() {
    co_await writer_.write(kFinalChunk);
    co_await writer_.close();

    co_return;
}

}  // namespace silkworm::rpc
