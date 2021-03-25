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

#ifndef SILKWORM_CRYPTO_RMD160_HPP_
#define SILKWORM_CRYPTO_RMD160_HPP_

#include <gsl/span>

#include <silkworm/common/base.hpp>

namespace silkworm::crypto {

void calculate_ripemd_160(gsl::span<uint8_t, 20> out, ByteView in) noexcept;

}

#endif  // SILKWORM_CRYPTO_RMD160_HPP_
