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

#ifndef SILKWORM_COMMON_BITS_HPP_
#define SILKWORM_COMMON_BITS_HPP_

#include <cstdint>

namespace silkworm {

//! \brief Returns the minimum number of bits required to represent x; the result is 0 for x == 0.
int bitlen_16(uint16_t x);

//! \brief Returns the number of trailing zero bits in x; the result is 16 for x == 0.
int ctz_16(uint16_t x);

//! \brief Returns the number of one bits ("population count") in x.
int popcount_16(uint64_t x);


} // namespace silkworm

#endif  // SILKWORM_COMMON_BITS_HPP_
