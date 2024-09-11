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
#include <set>
#include <string>
#include <variant>

#include <silkworm/core/types/block_id.hpp>
#include <silkworm/core/types/hash.hpp>

namespace silkworm::execution::api {

using BlockNumAndHash = BlockId;

struct ValidChain {
    BlockNumAndHash current_head;
};

struct InvalidChain {
    BlockNumAndHash unwind_point;
    std::optional<Hash> bad_block;
    std::set<Hash> bad_headers;
};

struct ValidationError {
    BlockNumAndHash latest_valid_head;
    std::string error;
};

using ValidationResult = std::variant<ValidChain, InvalidChain, ValidationError>;
using VerificationResult = ValidationResult;

}  // namespace silkworm::execution::api
