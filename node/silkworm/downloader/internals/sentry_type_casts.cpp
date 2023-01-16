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

#include "sentry_type_casts.hpp"

namespace silkworm {

// helpers

constexpr uint64_t lo_lo(const intx::uint256& x) { return x[0]; }

constexpr uint64_t lo_hi(const intx::uint256& x) { return x[1]; }

constexpr uint64_t hi_lo(const intx::uint256& x) { return x[2]; }

constexpr uint64_t hi_hi(const intx::uint256& x) { return x[3]; }

// implementation
std::unique_ptr<types::H256> to_H256(const intx::uint256& orig) {
    using types::H128, types::H256;

    auto dest = std::make_unique<H256>();

    H128* hi = new H128{};
    H128* lo = new H128{};

    hi->set_hi(hi_hi(orig));
    hi->set_lo(hi_lo(orig));
    lo->set_hi(lo_hi(orig));
    lo->set_lo(lo_lo(orig));

    dest->set_allocated_hi(hi);  // take ownership
    dest->set_allocated_lo(lo);  // take ownership

    return dest;  // transfer ownership
}

std::unique_ptr<types::H256> to_H256(const Hash& orig) {
    using types::H128, types::H256, evmc::load64be;

    H128* hi = new H128{};
    H128* lo = new H128{};

    hi->set_hi(load64be(orig.bytes + 0));
    hi->set_lo(load64be(orig.bytes + 8));
    lo->set_hi(load64be(orig.bytes + 16));
    lo->set_lo(load64be(orig.bytes + 24));

    auto dest = std::make_unique<H256>();
    dest->set_allocated_hi(hi);  // take ownership
    dest->set_allocated_lo(lo);  // take ownership

    return dest;  // transfer ownership
}

}  // namespace silkworm
