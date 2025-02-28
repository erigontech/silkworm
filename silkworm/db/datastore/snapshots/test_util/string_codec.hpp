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
    void decode_word(BytesOrByteView& input_word) override {
        if (input_word.holds_bytes()) {
            value = bytes_to_string(std::move(std::get<Bytes>(input_word)));
        } else {
            value = byte_view_to_string_view(std::get<ByteView>(input_word));
        }
    }
};

}  // namespace silkworm::snapshots
