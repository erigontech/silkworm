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

#include "seg_stream.hpp"

#include <functional>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/node/snapshots/seg/common/varint.hpp>

namespace silkworm::snapshots::seg {

using namespace std;

SegStream::SegStream(const filesystem::path& path)
    : file_(path, ios::in | ios::out | ios::binary | ios::trunc),
      stream_(file_),
      bit_stream_([this](uint8_t b) { stream_.write(byte_ptr_cast(&b), 1); }) {
    stream_.exceptions(ios::failbit | ios::badbit);
}

SegStream::SegStream(ostream& stream)
    : stream_(stream),
      bit_stream_([this](uint8_t b) { stream_.write(byte_ptr_cast(&b), 1); }) {
    stream_.exceptions(ios::failbit | ios::badbit);
}

void SegStream::write_big_endian(size_t value) {
    encoded_buf_.resize(sizeof(uint64_t));
    endian::store_big_u64(encoded_buf_.data(), value);
    stream_ << byte_view_to_string_view(encoded_buf_);
}

void SegStream::write_varint(size_t value) {
    stream_ << byte_view_to_string_view(varint::encode(encoded_buf_, value));
}

class ScopedSegHeaderSectionSizeWriter {
  public:
    ScopedSegHeaderSectionSizeWriter(
        ostream& stream,
        function<void(size_t)> write_size)
        : stream_(stream),
          write_size_(std::move(write_size)) {
        section_size_offset_ = stream_.tellp();
        // write a section size placeholder
        write_size_(0);
        section_start_offset_ = stream_.tellp();
    }

    ~ScopedSegHeaderSectionSizeWriter() {
        // calculate the section size
        auto section_end_offset = stream_.tellp();
        auto section_size = static_cast<size_t>(section_end_offset - section_start_offset_);

        // rewind and overwrite the section size
        stream_.seekp(section_size_offset_);
        write_size_(section_size);

        // go back
        stream_.seekp(section_end_offset);
    }

  private:
    ostream& stream_;
    function<void(size_t)> write_size_;
    ostream::pos_type section_size_offset_;
    ostream::pos_type section_start_offset_;
};

void SegStream::write_header(const Header& header) {
    write_big_endian(header.words_count);
    write_big_endian(header.empty_words_count);

    {
        ScopedSegHeaderSectionSizeWriter section_size{
            stream_,
            [this](size_t value) { write_big_endian(value); },
        };

        for (auto& symbol : header.patterns) {
            write_varint(symbol.code_bits);
            write_varint(symbol.data.size());
            stream_ << byte_view_to_string_view(symbol.data);
        }
    }

    {
        ScopedSegHeaderSectionSizeWriter section_size{
            stream_,
            [this](size_t value) { write_big_endian(value); },
        };

        for (auto& symbol : header.positions) {
            write_varint(symbol.code_bits);
            write_varint(symbol.data);
        }
    }
}

void SegStream::write_uncovered_data(ByteView data) {
    stream_ << byte_view_to_string_view(data);
}

}  // namespace silkworm::snapshots::seg
