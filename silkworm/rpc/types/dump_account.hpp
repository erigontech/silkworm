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

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::rpc {

using Storage = std::map<evmc::bytes32, silkworm::Bytes>;

struct DumpAccount {
    intx::uint256 balance{};
    uint64_t nonce{0};
    uint64_t incarnation{0};
    evmc::bytes32 root{0};
    evmc::bytes32 code_hash{0};
    std::optional<silkworm::Bytes> code;
    std::optional<Storage> storage;
};

using AccountsMap = std::map<evmc::address, DumpAccount>;

struct DumpAccounts {
    evmc::bytes32 root{0};
    evmc::address next{0};
    AccountsMap accounts;

    std::string to_string() const;
};

std::ostream& operator<<(std::ostream& out, const DumpAccounts& dump);

void to_json(nlohmann::json& json, const DumpAccounts& dump);
void to_json(nlohmann::json& json, const DumpAccount& dump_account);

}  // namespace silkworm::rpc
