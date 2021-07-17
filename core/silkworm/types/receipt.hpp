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

#ifndef SILKWORM_TYPES_RECEIPT_HPP_
#define SILKWORM_TYPES_RECEIPT_HPP_

#include <optional>

#include <silkworm/types/bloom.hpp>
#include <silkworm/types/log.hpp>
#include <silkworm/types/transaction.hpp>

namespace silkworm {

struct Receipt {
    Transaction::Type type{Transaction::Type::kLegacy};
    bool success{false};
    uint64_t cumulative_gas_used{0};
    Bloom bloom;
    std::vector<Log> logs;
};

}  // namespace silkworm

#endif  // SILKWORM_TYPES_RECEIPT_HPP_
