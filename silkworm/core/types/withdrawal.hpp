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

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/decode.hpp>

namespace silkworm {

struct Withdrawal {
    uint64_t index{0};
    uint64_t validator_index{0};
    evmc::address address{};
    uint64_t amount{0};  // in GWei

    friend bool operator==(const Withdrawal&, const Withdrawal&) = default;
};

namespace rlp {
    size_t length(const Withdrawal&);
    void encode(Bytes& to, const Withdrawal&);
    DecodingResult decode(ByteView& from, Withdrawal& to, Leftover mode = Leftover::kProhibit) noexcept;
}  // namespace rlp

}  // namespace silkworm
