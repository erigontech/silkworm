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

#include <stdint.h>  // for uint64_t

#include <optional>
#include <vector>  // for vector

#include <silkworm/core/types/bloom.hpp>        // for Bloom
#include <silkworm/core/types/log.hpp>          // for Log
#include <silkworm/core/types/transaction.hpp>  // for TransactionType, Tran...

#include "silkworm/core/common/base.hpp"  // for Bytes

namespace silkworm {

struct Receipt {
    TransactionType type{TransactionType::kLegacy};
    bool success{false};
    uint64_t cumulative_gas_used{0};
    Bloom bloom;
    std::vector<Log> logs;
};

namespace rlp {
    void encode(Bytes& to, const Receipt&);
}

}  // namespace silkworm
