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

#ifndef SILKWORM_EXECUTION_STATE_POOL_H_
#define SILKWORM_EXECUTION_STATE_POOL_H_

#include <memory>
#include <vector>

namespace evmone {
struct execution_state;
}

namespace silkworm {

class ExecutionStatePool {
 public:
  static ExecutionStatePool& instance();

  ExecutionStatePool(const ExecutionStatePool&) = delete;
  ExecutionStatePool& operator=(const ExecutionStatePool&) = delete;

  void add(std::unique_ptr<evmone::execution_state> new_object);

  bool spare_objects() const;

  // may only be called if spare_objects
  evmone::execution_state* grab();

  void release();

 private:
  ExecutionStatePool() {}

  std::vector<std::unique_ptr<evmone::execution_state>> objects_{};
  size_t in_use_{0};
};
}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_STATE_POOL_H_
