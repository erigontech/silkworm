/*
   Copyright 2023 The Silkworm Authors

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

#include <silkworm/infra/concurrency/idle_strategy.hpp>

namespace silkworm::concurrency {

//! Default number of threads to use for I/O tasks
inline const auto kDefaultNumContexts{std::thread::hardware_concurrency() / 2};

//! The configuration settings for \refitem ContextPool
struct ContextPoolSettings {
    uint32_t num_contexts{kDefaultNumContexts};  // The number of execution contexts to activate
    WaitMode wait_mode{WaitMode::blocking};      // The waiting strategy when context has no work
};

}  // namespace silkworm::concurrency
