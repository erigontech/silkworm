// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "raw_words_stream.hpp"

#include <stdexcept>

#include <silkworm/core/common/bytes_to_string.hpp>

#include "../common/varint.hpp"

namespace silkworm::snapshots::seg {

using namespace std;

RawWordsStream::RawWordsStream(const filesystem::path& path, OpenMode open_mode, size_t buffer_size)
    : file_(path, ios::in | ios::out | ios::binary | ((open_mode == OpenMode::kCreate) ? ios::trunc : ios::openmode{})),
      stream_(file_) {
    stream_.exceptions(ios::failbit | ios::badbit);

    stream_buffer_.reset(new char[buffer_size]);
    stream_.rdbuf()->pubsetbuf(stream_buffer_.get(), static_cast<streamsize>(buffer_size));
}

RawWordsStream::RawWordsStream(iostream& stream) : stream_(stream) {
    stream_.exceptions(ios::failbit | ios::badbit);
}

void RawWordsStream::write_word(ByteView word, bool is_compressed) {
    // the length is shifted to store the is_compressed flag
    size_t length = (word.size() << 1) | (is_compressed ? 0 : 1);
    stream_ << byte_view_to_string_view(varint::encode(encoded_length_, length));
    stream_ << byte_view_to_string_view(word);
}

std::optional<pair<Bytes, bool>> RawWordsStream::read_word() {
    if (stream_.peek() == decltype(file_)::traits_type::eof())
        return nullopt;

    auto encoded_length = varint::read(encoded_length_, [this]() -> char {
        char c = 0;
        this->stream_.get(c);
        return c;
    });
    if (!encoded_length)
        throw runtime_error("RawWordsStream::read_word failed to read length at " + std::to_string(stream_.tellg()));

    auto length = varint::decode(*encoded_length);
    if (!length)
        throw runtime_error("RawWordsStream::read_word failed to parse length at " + std::to_string(stream_.tellg()));

    bool is_compressed = !(*length & 1);
    size_t size = *length >> 1;

    Bytes word(size, 0);
    stream_.read(byte_ptr_cast(word.data()), static_cast<streamsize>(word.size()));

    return pair<Bytes, bool>{word, is_compressed};
}

}  // namespace silkworm::snapshots::seg
