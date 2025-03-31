// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bit_stream.hpp"

#include <cstdint>

namespace silkworm::snapshots::seg {

void BitStream::write(uint64_t code, uint8_t code_bits) {
    while (code_bits > 0) {
        uint8_t bits_used = (output_bits_ + code_bits > 8) ? (8 - output_bits_) : code_bits;
        uint64_t mask = (uint64_t{1} << bits_used) - 1;

        output_byte_ |= static_cast<uint8_t>((code & mask) << output_bits_);
        code >>= bits_used;
        code_bits -= bits_used;
        output_bits_ += bits_used;

        if (output_bits_ == 8) {
            flush();
        }
    }
}

BitStream::~BitStream() {
    flush();
}

void BitStream::flush() {
    if (output_bits_ > 0) {
        byte_writer_(output_byte_);
        output_bits_ = 0;
        output_byte_ = 0;
    }
}

}  // namespace silkworm::snapshots::seg
