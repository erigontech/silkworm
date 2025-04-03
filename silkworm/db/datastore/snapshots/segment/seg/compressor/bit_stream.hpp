// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <functional>

namespace silkworm::snapshots::seg {

class BitStream {
  public:
    explicit BitStream(std::function<void(uint8_t)> byte_writer)
        : byte_writer_(std::move(byte_writer)) {}
    ~BitStream();

    void write(uint64_t code, uint8_t code_bits);
    void flush();

  private:
    std::function<void(uint8_t)> byte_writer_;
    uint8_t output_bits_{};
    uint8_t output_byte_{};
};

}  // namespace silkworm::snapshots::seg
