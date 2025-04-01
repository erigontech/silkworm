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

#include "log.hpp"

#include <iomanip>
#include <sstream>

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Log& log) {
    out << log.to_string();
    return out;
}

std::string Log::to_string() const {
    const auto& log = *this;
    std::stringstream out;

    out << "#topics: " << log.topics.size();
    out << " #data: " << log.data.size();
    out << " block_num: " << static_cast<uint32_t>(log.block_num);
    out << " tx_hash: " << to_hex(log.tx_hash);
    out << " tx_index: " << log.tx_index;
    out << " block_hash: " << to_hex(log.block_hash);
    out << " index: " << log.index;
    out << " removed: " << log.removed;
    out << " address: ";
    for (const auto& b : log.address.bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << int{b};
    }
    out << std::dec;
    return out.str();
}

}  // namespace silkworm::rpc
