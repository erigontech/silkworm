/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_CONCURRENCY_THREAD_SAFE_STATE_POOL_HPP_
#define SILKWORM_CONCURRENCY_THREAD_SAFE_STATE_POOL_HPP_

#include <mutex>

#include <silkworm/execution/state_pool.hpp>

namespace silkworm {

class ThreadSafeExecutionStatePool : public ExecutionStatePool {
  public:
    std::unique_ptr<evmone::AdvancedExecutionState> acquire() noexcept override;

    void release(std::unique_ptr<evmone::AdvancedExecutionState> obj) noexcept override;

  private:
    std::mutex mutex_;
};

}  // namespace silkworm

#endif  // SILKWORM_CONCURRENCY_THREAD_SAFE_STATE_POOL_HPP_
