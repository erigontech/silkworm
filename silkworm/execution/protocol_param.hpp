/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_EXECUTION_PROTOCOL_PARAM_H_
#define SILKWORM_EXECUTION_PROTOCOL_PARAM_H_

#include <stdint.h>

#include <silkworm/common/base.hpp>

namespace silkworm {

// Fee schedule—see Appendix G of the Yellow Paper
// https://ethereum.github.io/yellowpaper/paper.pdf
namespace fee {
constexpr uint64_t kGSLoadTangerineWhistle{200};
constexpr uint64_t kGSLoadIstanbul{800};

constexpr uint64_t kGSSet{20'000};
constexpr uint64_t kGSReset{5'000};

constexpr uint64_t kRSClear{15'000};
constexpr uint64_t kRSelfDestruct{24'000};

constexpr uint64_t kGCodeDeposit{200};

constexpr uint64_t kGTxCreate{32'000};
constexpr uint64_t kGTxDataZero{4};
constexpr uint64_t kGTxDataNonZeroFrontier{68};
constexpr uint64_t kGTxDataNonZeroEIP2028{16};
constexpr uint64_t kGTransaction{21'000};

constexpr uint64_t kGQuadDivisor{20};
}  // namespace fee

namespace param {
// https://eips.ethereum.org/EIPS/eip-170
constexpr size_t kMaxCodeSize{0x6000};

constexpr uint64_t kFrontierBlockReward{5 * kEther};
constexpr uint64_t kByzantiumBlockReward{3 * kEther};
constexpr uint64_t kConstantinopleBlockReward{2 * kEther};
}  // namespace param
}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_PROTOCOL_PARAM_H_
