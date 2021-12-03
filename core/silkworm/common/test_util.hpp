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

#ifndef SILKWORM_COMMON_TEST_UTIL_HPP_
#define SILKWORM_COMMON_TEST_UTIL_HPP_

#include <silkworm/types/block.hpp>
#include <silkworm/types/receipt.hpp>

namespace silkworm::test {

/// Enables London from genesis.
inline constexpr ChainConfig kLondonConfig{
    1,  // chain_id
    SealEngineType::kNoProof,
    {0, 0, 0, 0, 0, 0, 0, 0, 0},
    std::nullopt,  // dao_block
    0,             // muir_glacier_block
};

static_assert(kLondonConfig.revision(0) == EVMC_LONDON);

std::vector<Transaction> sample_transactions();
std::vector<Receipt> sample_receipts();

}  // namespace silkworm::test

#endif  // SILKWORM_COMMON_TEST_UTIL_HPP_
