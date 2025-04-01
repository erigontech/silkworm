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
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::rpc {

struct Log {
    /* raw fields */
    evmc::address address;
    std::vector<evmc::bytes32> topics;
    silkworm::Bytes data;

    /* derived fields */
    BlockNum block_num{0};
    evmc::bytes32 tx_hash;
    uint32_t tx_index{0};
    evmc::bytes32 block_hash;
    uint32_t index{0};
    bool removed{false};
    std::optional<uint64_t> timestamp{std::nullopt};

    std::string to_string() const;
};

using Logs = std::vector<Log>;

std::ostream& operator<<(std::ostream& out, const Log& log);

}  // namespace silkworm::rpc
