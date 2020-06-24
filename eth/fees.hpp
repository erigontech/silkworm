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

#ifndef SILKWORM_ETH_FEES_H_
#define SILKWORM_ETH_FEES_H_

#include <stdint.h>

namespace silkworm::eth::fees {

uint64_t kRsclear{15000};

uint64_t kGtxCreate{32000};
uint64_t kGtxDataZero{4};
uint64_t kGtxDataNonZeroFrontier{68};
uint64_t kGtxDataNonZeroEIP2028{16};
uint64_t kGtransaction{21000};

}  // namespace silkworm::eth::fees

#endif  // SILKWORM_ETH_FEES_H_
