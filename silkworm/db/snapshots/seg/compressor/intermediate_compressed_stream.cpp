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

#include "intermediate_compressed_stream.hpp"

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/snapshots/seg/common/varint.hpp>

namespace silkworm::snapshots::seg {

using namespace std;

IntermediateCompressedStream::IntermediateCompressedStream(
    const filesystem::path& path,
    size_t buffer_size)
    : file_(path, ios::in | ios::out | ios::binary | ios::trunc),
      stream_(file_) {
    stream_.exceptions(ios::failbit | ios::badbit);

    stream_buffer_.reset(new char[buffer_size]);
    stream_.rdbuf()->pubsetbuf(stream_buffer_.get(), static_cast<streamsize>(buffer_size));
}

IntermediateCompressedStream::IntermediateCompressedStream(iostream& stream) : stream_(stream) {
    stream_.exceptions(ios::failbit | ios::badbit);
}

void IntermediateCompressedStream::write_varint(size_t value) {
    stream_ << byte_view_to_string_view(varint::encode(encoded_buf_, value));
}

void IntermediateCompressedStream::write_word(const CompressedWord& word) {
    write_varint(word.raw_length);
    if (word.raw_length == 0) return;

    write_varint(word.pattern_positions.size());
    for (auto [pattern_pos, pattern_code] : word.pattern_positions) {
        write_varint(pattern_pos);
        write_varint(pattern_code);
    }
}

void IntermediateCompressedStream::write_uncovered_data(silkworm::ByteView data) {
    stream_ << byte_view_to_string_view(data);
}

size_t IntermediateCompressedStream::read_varint() {
    auto encoded_value = varint::read(encoded_buf_, [this]() -> char {
        char c = 0;
        this->stream_.get(c);
        return c;
    });
    if (!encoded_value)
        throw runtime_error("IntermediateCompressedStream::read_varint failed to read at " + std::to_string(stream_.tellg()));

    auto value = varint::decode(*encoded_value);
    if (!value)
        throw runtime_error("IntermediateCompressedStream::read_varint failed to parse at " + std::to_string(stream_.tellg()));

    return *value;
}

std::optional<IntermediateCompressedStream::CompressedWord> IntermediateCompressedStream::read_word() {
    if (stream_.peek() == decltype(file_)::traits_type::eof())
        return nullopt;

    CompressedWord word;
    word.raw_length = read_varint();
    if (word.raw_length == 0)
        return word;

    size_t pattern_positions_count = read_varint();
    word.pattern_positions.reserve(pattern_positions_count);
    while (pattern_positions_count > 0) {
        size_t pattern_pos = read_varint();
        size_t pattern_code = read_varint();
        word.pattern_positions.emplace_back(pattern_pos, pattern_code);
        pattern_positions_count--;
    }

    return word;
}

Bytes IntermediateCompressedStream::read_uncovered_data(size_t size) {
    Bytes data(size, 0);
    stream_.read(byte_ptr_cast(data.data()), static_cast<streamsize>(data.size()));
    return data;
}

}  // namespace silkworm::snapshots::seg
