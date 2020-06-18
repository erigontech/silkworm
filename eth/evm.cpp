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

#include "evm.hpp"

#include <gsl/gsl_assert>
#include <limits>

namespace silkworm::eth {

GasPool& GasPool::operator+=(uint64_t amount) {
  if (gas_ > std::numeric_limits<uint64_t>::max() - amount) {
    throw std::overflow_error{"gas pool pushed above uint64"};
  }
  gas_ += amount;
  return *this;
}

GasPool& GasPool::operator-=(uint64_t amount) {
  if (gas_ < amount) {
    throw GasLimitReached{};
  }
  gas_ -= amount;
  return *this;
}

ExecutionResult Execute(const Transaction& txn, GasPool&) {
  Expects(txn.from);
  // TODO (Andrew) implement
  return ExecutionResult{};
}

}  // namespace silkworm::eth
