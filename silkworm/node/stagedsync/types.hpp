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

#include <set>
#include <variant>
#include <vector>

#include <silkworm/core/types/block.hpp>

namespace silkworm::execution {

using BlockVector = std::vector<std::shared_ptr<Block>>;

struct ForkChoiceApplication {
    bool success{false};  // Fork choice is either successful or unsuccessful.
    Hash current_head;    // Return latest valid hash in case of halt of execution.
    BlockNum current_height{0};
};

struct ValidChain {
    Hash current_head;
};

struct InvalidChain {
    Hash latest_valid_head;
    std::optional<Hash> bad_block;
    std::set<Hash> bad_headers;
};

struct ValidationError {
    Hash latest_valid_head;
    std::string error;
};

using ValidationResult = std::variant<ValidChain, InvalidChain, ValidationError>;

}  // namespace silkworm::execution
