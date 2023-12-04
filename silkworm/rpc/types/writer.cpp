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

#include <algorithm>
#include <charconv>
#include <iostream>
#include <utility>

#include <boost/asio/detached.hpp>
#include <boost/asio/write.hpp>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc {

const std::string kChunkSep{'\r', '\n'};                     // NOLINT(runtime/string)
const std::string kFinalChunk{'0', '\r', '\n', '\r', '\n'};  // NOLINT(runtime/string)

ChunksWriter::ChunksWriter(Writer& writer, std::size_t chunk_size)
    : writer_(writer), chunk_size_(chunk_size), available_(chunk_size_), buffer_{new char[chunk_size_]} {
    std::memset(buffer_.get(), 0, chunk_size_);
}

void ChunksWriter::write(std::string_view content) {
    auto c_str = content.data();
    auto size = content.size();

    SILK_DEBUG << "ChunksWriter::write available_: " << available_ << " size: " << size;

    char* buffer_start = buffer_.get() + (chunk_size_ - available_);
    if (available_ > size) {
        std::memcpy(buffer_start, c_str, size);
        available_ -= size;
        return;
    }

    while (size > 0) {
        const auto count = std::min(available_, size);
        std::memcpy(buffer_start, c_str, count);
        size -= count;
        c_str += count;
        available_ -= count;
        if (available_ > 0) {
            break;
        }
        flush();

        buffer_start = buffer_.get();
    }
}

void ChunksWriter::close() {
    flush();
    writer_.write(kFinalChunk);
    writer_.close();
}

void ChunksWriter::flush() {
    auto size = chunk_size_ - available_;
    SILK_DEBUG << "ChunksWriter::flush available_: " << available_ << " size: " << size;

    if (size > 0) {
        std::array<char, 19> str;
        if (auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), size, 16); ec == std::errc()) {
            writer_.write(std::string_view(str.data(), ptr));
            writer_.write(kChunkSep);
        } else {
            writer_.write("Invalid value");
        }

        writer_.write(std::string_view(buffer_.get(), size));
        writer_.write(kChunkSep);
    }
    available_ = chunk_size_;
}

JsonChunksWriter::JsonChunksWriter(Writer& writer, std::size_t chunk_size)
    : writer_(writer), chunk_size_(chunk_size), room_left_in_chunck_(chunk_size_), written_(0) {
    str_chunk_size_ << std::hex << chunk_size_ << kChunkSep;
}

void JsonChunksWriter::write(std::string_view content) {
    auto size = content.size();

    SILK_DEBUG << "JsonChunksWriter::write written_: " << written_ << " size: " << size;

    if (!chunk_open_) {
        writer_.write(str_chunk_size_.str());
        chunk_open_ = true;
    }

    size_t remaining_in_view = size;
    size_t start = 0;
    while (start < size) {
        const auto length = std::min(room_left_in_chunck_, remaining_in_view);
        std::string_view sub_view(content.data() + start, length);
        writer_.write(sub_view);

        written_ += length;
        start += length;
        remaining_in_view -= length;
        room_left_in_chunck_ -= length;

        if ((room_left_in_chunck_ % chunk_size_) == 0) {
            if (chunk_open_) {
                writer_.write(kChunkSep);
                room_left_in_chunck_ = chunk_size_;
                chunk_open_ = false;
            }
            if (remaining_in_view > 0) {
                writer_.write(str_chunk_size_.str());
                chunk_open_ = true;
            }
        }
    }
}

void JsonChunksWriter::close() {
    if (chunk_open_) {
        if (room_left_in_chunck_ > 0) {
            std::unique_ptr<char[]> buffer{new char[room_left_in_chunck_]};
            std::memset(buffer.get(), ' ', room_left_in_chunck_);
            writer_.write(std::string_view(buffer.get(), room_left_in_chunck_));
        }
        writer_.write(kChunkSep);
        chunk_open_ = false;
        room_left_in_chunck_ = chunk_size_;
    }

    writer_.write(kFinalChunk);
    writer_.close();
}

}  // namespace silkworm::rpc
