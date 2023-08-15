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

#include <cstddef>

#include <silkworm/infra/concurrency/task.hpp>

#include <absl/functional/function_ref.h>

namespace silkworm::rpc {

using BinaryPredicate = absl::FunctionRef<Task<bool>(std::size_t)>;

Task<std::size_t> binary_search(std::size_t n, BinaryPredicate pred);

}  // namespace silkworm::rpc
