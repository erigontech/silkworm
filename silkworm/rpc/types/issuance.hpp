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

#include <iostream>
#include <optional>
#include <string>

namespace silkworm::rpc {

struct Issuance {
    std::optional<std::string> block_reward;
    std::optional<std::string> ommer_reward;
    std::optional<std::string> issuance;
    std::optional<std::string> burnt;
    std::optional<std::string> total_issued;
    std::optional<std::string> total_burnt;
    std::optional<std::string> tips;
};

std::ostream& operator<<(std::ostream& out, const Issuance& issuance);

}  // namespace silkworm::rpc
