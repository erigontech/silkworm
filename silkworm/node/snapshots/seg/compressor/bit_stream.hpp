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

#include <cstdint>
#include <functional>

namespace silkworm::snapshots::seg {

class BitStream {
  public:
    BitStream(std::function<void(uint8_t)> byte_writer)
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
