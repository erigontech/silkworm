/*  hasher.cpp
 *
 *  This file is part of Mammon.
 *  mammon is a greedy and selfish ETH consensus client.
 *
 *  Copyright (c) 2021 - Reimundo Heluani (potuz) potuz@potuz.net
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#if (__x86_64__ || __i386__)
#include <cpuid.h>
#endif

#include <silkworm/core/common/base.hpp>
#include <silkworm/lightclient/ssz/chunk.hpp>
#include <silkworm/lightclient/ssz/hasher.hpp>
#include <silkworm/sentry/rlpx/crypto/sha3_hasher.hpp>  // TODO(canepat) refactor

#if (__x86_64__ || __i386__)
namespace {
constexpr auto CPUID_LEAF = 7;
}
#endif

namespace ssz {

void Hasher::sha256_basic(unsigned char* output, const unsigned char* input, std::size_t blocks) {
    silkworm::sentry::rlpx::crypto::Sha3Hasher hasher;
    while (blocks) {
        hasher.update({input, 2 * silkworm::kHashLength});
        silkworm::Bytes hash = hasher.hash();
        std::copy(hash.cbegin(), hash.cend(), output);
        input += 2 * silkworm::kHashLength;
        output += silkworm::kHashLength;
        blocks--;
    }
}

Hasher::IMPL Hasher::implemented() {
    IMPL ret = IMPL::NONE;
#if (__x86_64__ || __i386__)
    std::uint32_t a{0}, b{0}, c{0}, d{0};
    __get_cpuid_count(CPUID_LEAF, 0, &a, &b, &c, &d);
    if (b & bit_SHA) ret = ret | IMPL::SHA;
    if (b & bit_AVX2) ret = ret | IMPL::AVX2;

    __get_cpuid(1, &a, &b, &c, &d);
    if (c & bit_AVX) ret = ret |  IMPL::AVX;
    if (c & bit_SSE3) ret = ret | IMPL::SSE;
#endif
    return ret;
}

Hasher::SHA256_hasher Hasher::best_sha256_implementation() {
    return &sha256_basic;
}

}  // namespace ssz
