/*
   Copyright 2022 The Silkworm Authors

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

#include "types.hpp"

#include <magic_enum.hpp>

namespace silkworm {

std::ostream& operator<<(std::ostream& os, const PeerPenalization& penalization) {
    os << penalization.to_string();
    return os;
}

std::string PeerPenalization::to_string() const {
    const auto& penalization = *this;
    std::stringstream os;

    os << "peer_id=" << penalization.peer_id << " cause=" << magic_enum::enum_name(penalization.penalty);
    return os.str();
}

}  // namespace silkworm
