/*
   Copyright 2022 The Silkworm Authors

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

// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

// Platform-specific functions and macros

// Microsoft Visual Studio
#if defined(_MSC_VER) && (_MSC_VER < 1600)
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;
// Other compilers
#else  // defined(_MSC_VER)
#include <cstdint>
#endif  // !defined(_MSC_VER)

namespace silkworm::snapshots::encoding {

void murmur_hash3_x64_128(const void* key, uint64_t len, uint32_t seed, void* out);

class Murmur3 {
  public:
    explicit Murmur3(uint32_t seed) : seed_(seed) {}

    void reset_seed(uint32_t seed) noexcept {
        seed_ = seed;
    }

    void hash_x64_128(const void* key, uint64_t len, void* out) const {
        murmur_hash3_x64_128(key, len, seed_, out);
    }

  private:
    uint32_t seed_;
};

}  // namespace silkworm::snapshots::encoding
