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

#include "bloom.hpp"

#include <ethash/keccak.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm {

// See Section 4.3.1 "Transaction Receipt" of the Yellow Paper
static void m3_2048(Bloom& bloom, ByteView x) {
    ethash::hash256 hash{keccak256(x)};
    for (unsigned i{0}; i < 6; i += 2) {
        unsigned bit{(hash.bytes[i + 1] + (hash.bytes[i] << 8)) & 0x7FFu};
        bloom[kBloomByteLength - 1 - bit / 8] |= 1 << (bit % 8);
    }
}

Bloom logs_bloom(const std::vector<Log>& logs) {
    Bloom bloom{};  // zero initialization
    for (const Log& log : logs) {
        m3_2048(bloom, full_view(log.address));
        for (const auto& topic : log.topics) {
            m3_2048(bloom, full_view(topic));
        }
    }
    return bloom;
}
}  // namespace silkworm
