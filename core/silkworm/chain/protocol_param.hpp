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

#include <cstdint>

#include <silkworm/common/base.hpp>

namespace silkworm {

// Gas fee schedule—see Appendix G of the Yellow Paper
// https://ethereum.github.io/yellowpaper/paper.pdf
namespace fee {

    inline constexpr uint64_t kAccessListStorageKeyCost{1'900};  // EIP-2930
    inline constexpr uint64_t kAccessListAddressCost{2'400};     // EIP-2930

    inline constexpr uint64_t kGCodeDeposit{200};

    inline constexpr uint64_t kGTransaction{21'000};
    inline constexpr uint64_t kGTxCreate{32'000};
    inline constexpr uint64_t kGTxDataZero{4};
    inline constexpr uint64_t kGTxDataNonZeroFrontier{68};
    inline constexpr uint64_t kGTxDataNonZeroIstanbul{16};  // EIP-2028

    inline constexpr uint64_t kInitCodeWordCost{2};  // EIP-3860

}  // namespace fee

namespace param {

    inline constexpr size_t kMaxCodeSize{0x6000};                // EIP-170
    inline constexpr size_t kMaxInitCodeSize{2 * kMaxCodeSize};  // EIP-3860

    inline constexpr uint64_t kMaxExtraDataBytes{32};

    inline constexpr uint64_t kBlockRewardFrontier{5 * kEther};
    inline constexpr uint64_t kBlockRewardByzantium{3 * kEther};       // EIP-649
    inline constexpr uint64_t kBlockRewardConstantinople{2 * kEther};  // EIP-1234

    // EIP-3529: Reduction in refunds
    inline constexpr uint64_t kMaxRefundQuotientFrontier{2};
    inline constexpr uint64_t kMaxRefundQuotientLondon{5};

    // EIP-1559: Fee market change for ETH 1.0 chain
    inline constexpr uint64_t kInitialBaseFee{kGiga};
    inline constexpr uint64_t kBaseFeeMaxChangeDenominator{8};
    inline constexpr uint64_t kElasticityMultiplier{2};

}  // namespace param

}  // namespace silkworm
