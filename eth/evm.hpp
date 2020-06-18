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

#ifndef SILKWORM_ETH_EVM_H_
#define SILKWORM_ETH_EVM_H_

#include <stdint.h>

#include <stdexcept>
#include <string>

#include "transaction.hpp"

namespace silkworm::eth {

class GasLimitReached : public std::runtime_error {
 public:
  GasLimitReached() : std::runtime_error{"gas limit reached"} {}
};

class GasPool {
 public:
  uint64_t gas() const { return gas_; }

  GasPool& operator+=(uint64_t amount);
  GasPool& operator-=(uint64_t amount);

 private:
  uint64_t gas_{0};
};

struct ExecutionResult {
  uint64_t used_gas{0};
  // TODO(Andrew) err;
  std::string return_data;
};

class EVM {
 public:
  // precondition: txn.from must be recovered
  ExecutionResult Execute(const Transaction& txn, GasPool& available_gas);
};

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_EVM_H_
