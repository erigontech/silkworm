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

#include "issuance.hpp"

#include <sstream>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Issuance& issuance) {
    out << issuance.to_string();
    return out;
}

std::string Issuance::to_string() const {
    std::stringstream out;
    out << "block_reward: " << block_reward.value_or("null") << " "
        << "ommer_reward: " << ommer_reward.value_or("null") << " "
        << "issuance: " << issuance.value_or("null") << " ";
    return out.str();
}

}  // namespace silkworm::rpc
