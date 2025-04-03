// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
