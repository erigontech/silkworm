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

/*  hasher.hpp
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

#pragma once

#include <cstdint>
#include <cstddef>

extern "C" void sha256_4_avx(unsigned char* output, const unsigned char* input, std::size_t blocks);
extern "C" void sha256_8_avx2(unsigned char* output, const unsigned char* input, std::size_t blocks);
extern "C" void sha256_shani(unsigned char* output, const unsigned char* input, std::size_t blocks);

namespace silkworm::ssz {

class Hasher {
  public:
   enum class IMPL {
       NONE = 0,
       SSE  = 1,
       AVX  = 2,
       AVX2 = 4,
       SHA  = 8
   };

   inline friend IMPL operator |(IMPL a, IMPL b) noexcept {
       return static_cast<IMPL>(static_cast<int>(a) | static_cast<int>(b));
   }

   inline friend IMPL operator &(IMPL a, IMPL b) noexcept {
       return static_cast<IMPL>(static_cast<int>(a) & static_cast<int>(b));
   }

   inline friend bool operator !(IMPL a) noexcept { return a == IMPL::NONE; };

   Hasher() : _hash_64b_blocks { best_sha256_implementation() } {};
   // explicit Hasher(IMPL impl);

   inline constexpr void hash_64b_blocks(unsigned char* output, const unsigned char* input, std::size_t blocks) const {
       _hash_64b_blocks(output, input, blocks);
   }

   static IMPL implemented();

  private:
   typedef void (*SHA256_hasher)(unsigned char*, const unsigned char*, std::size_t);
   SHA256_hasher _hash_64b_blocks;

   static SHA256_hasher best_sha256_implementation();
#if (__x86_64__ || __i386__)
   static constexpr auto sha256_4_avx = ::sha256_4_avx;
   static constexpr auto sha256_8_avx2 = ::sha256_8_avx2;
   static constexpr auto sha256_shani = ::sha256_shani;
   static void sha256_sse(unsigned char* output, const unsigned char* input, std::size_t blocks);
#endif
   static void sha256_basic(unsigned char* output, const unsigned char* input, std::size_t blocks);
};

}  // namespace silkworm::ssz