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

#include "types.hpp"

#include <silkworm/common/endian.hpp>

namespace silkworm {

Hash hash_from_H256(const types::H256& orig) {
    uint64_t hi_hi = orig.hi().hi();
    uint64_t hi_lo = orig.hi().lo();
    uint64_t lo_hi = orig.lo().hi();
    uint64_t lo_lo = orig.lo().lo();

    Hash dest;
    endian::store_big_u64(dest.bytes + 0, hi_hi);
    endian::store_big_u64(dest.bytes + 8, hi_lo);
    endian::store_big_u64(dest.bytes + 16, lo_hi);
    endian::store_big_u64(dest.bytes + 24, lo_lo);

    return dest;
}

constexpr uint64_t& lo_lo(intx::uint256& x) { return x[0]; }
constexpr uint64_t& lo_hi(intx::uint256& x) { return x[1]; }
constexpr uint64_t& hi_lo(intx::uint256& x) { return x[2]; }
constexpr uint64_t& hi_hi(intx::uint256& x) { return x[3]; }

intx::uint256 uint256_from_H256(const types::H256& orig) {
    using types::H128, types::H256;

    intx::uint256 dest;
    hi_hi(dest) = orig.hi().hi();
    hi_lo(dest) = orig.hi().lo();
    lo_hi(dest) = orig.lo().hi();
    lo_lo(dest) = orig.lo().lo();

    return dest;
}

}  // namespace silkworm
