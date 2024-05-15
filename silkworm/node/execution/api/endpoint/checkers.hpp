/*
   Copyright 2024 The Silkworm Authors

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

#include <optional>
#include <string>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>

#include "status.hpp"

namespace silkworm::execution::api {

struct ForkChoice {
    Hash head_block_hash;
    uint64_t timeout{0};
    std::optional<Hash> finalized_block_hash;
    std::optional<Hash> safe_block_hash;
};

struct ForkChoiceResult {
    ExecutionStatus status;
    Hash latest_valid_head;
    std::string validation_error;

    operator bool() const { return success(status); }
};

}  // namespace silkworm::execution::api
