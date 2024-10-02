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

#include "xor.hpp"

#include <algorithm>
#include <functional>

namespace silkworm::sentry::crypto {

void xor_bytes(Bytes& data1, ByteView data2) {
    SILKWORM_ASSERT(data1.size() <= data2.size());
    std::transform(data1.cbegin(), data1.cend(), data2.cbegin(), data1.begin(), std::bit_xor<>{});
}

}  // namespace silkworm::sentry::crypto
