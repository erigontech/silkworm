// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/core/common/bytes_to_string.hpp>

#include "../common/codec.hpp"

namespace silkworm::snapshots {

struct StringCodec : public Codec {
    std::string value;
    Bytes word;

    ~StringCodec() override = default;

    ByteView encode_word() override {
        word = string_to_bytes(value);
        return word;
    }
    void decode_word(Word& input_word) override {
        if (input_word.holds_bytes()) {
            value = bytes_to_string(std::move(std::get<Bytes>(input_word)));
        } else {
            value = byte_view_to_string_view(std::get<ByteView>(input_word));
        }
    }
};

}  // namespace silkworm::snapshots
