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

#include "state_pool.hpp"

#include <utility>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <evmone/analysis.hpp>
#pragma GCC diagnostic pop

namespace silkworm {

ExecutionStatePool::ExecutionStatePool() {}

ExecutionStatePool::~ExecutionStatePool() {}

std::unique_ptr<evmone::AdvancedExecutionState> ExecutionStatePool::acquire() noexcept {
    if (pool_.empty()) {
        return std::make_unique<evmone::AdvancedExecutionState>();
    }
    std::unique_ptr<evmone::AdvancedExecutionState> obj{pool_.top().release()};
    pool_.pop();
    return obj;
}

void ExecutionStatePool::release(std::unique_ptr<evmone::AdvancedExecutionState> obj) noexcept {
    pool_.push(std::move(obj));
}

}  // namespace silkworm
