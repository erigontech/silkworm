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

#include "state_pool.hpp"

#include <cassert>
#include <utility>

#include "analysis.hpp"

namespace silkworm {

ExecutionStatePool& ExecutionStatePool::instance() noexcept {
    thread_local ExecutionStatePool x{};
    return x;
}

void ExecutionStatePool::add(std::unique_ptr<evmone::execution_state> new_object) noexcept {
    objects_.push_back(std::move(new_object));
}

bool ExecutionStatePool::spare_objects() const noexcept { return in_use_ < objects_.size(); }

evmone::execution_state* ExecutionStatePool::grab() noexcept {
    assert(in_use_ < objects_.size());
    return objects_[in_use_++].get();
}

void ExecutionStatePool::release() noexcept { --in_use_; }

}  // namespace silkworm
