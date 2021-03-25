/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "rmd160.hpp"

#include <silkworm/common/endian.hpp>

#include "rmd160.h"

namespace silkworm::crypto {

void calculate_ripemd_160(gsl::span<uint8_t, 20> out, ByteView in) noexcept {
    uint32_t buf[160 / 32];

    rmd160_init(buf);

    uint8_t const* ptr{in.data()};

    uint32_t current[16];
    for (size_t remaining{in.size()}; remaining >= 64; remaining -= 64) {
        for (unsigned i{0}; i < 16; ++i) {
            current[i] = endian::load_little_u32(ptr);
            ptr += 4;
        }
        rmd160_compress(buf, current);
    }

    rmd160_finish(buf, ptr, in.size(), /*mswlen=*/0);

    for (unsigned i{0}; i < 20; i += 4) {
        out[i] = buf[i >> 2];
        out[i + 1] = buf[i >> 2] >> 8;
        out[i + 2] = buf[i >> 2] >> 16;
        out[i + 3] = buf[i >> 2] >> 24;
    }
}

}  // namespace silkworm::crypto
