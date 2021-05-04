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

#ifndef SILKWORM_EXECUTION_STATE_POOL_HPP_
#define SILKWORM_EXECUTION_STATE_POOL_HPP_

#include <memory>
#include <stack>

namespace evmone {
struct AdvancedExecutionState;
}

namespace silkworm {

/// Object pool of EVM execution states.
class ExecutionStatePool {
  public:
    ExecutionStatePool();
    ~ExecutionStatePool();

    ExecutionStatePool(const ExecutionStatePool&) = delete;
    ExecutionStatePool& operator=(const ExecutionStatePool&) = delete;

    std::unique_ptr<evmone::AdvancedExecutionState> acquire() noexcept;

    void release(std::unique_ptr<evmone::AdvancedExecutionState> obj) noexcept;

  private:
    std::stack<std::unique_ptr<evmone::AdvancedExecutionState>> pool_;
};

}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_STATE_POOL_HPP_
