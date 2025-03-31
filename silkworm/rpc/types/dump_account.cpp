// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "dump_account.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const DumpAccounts& dump) {
    out << "root: 0x" << silkworm::to_hex(dump.root)
        << " next: " << dump.next
        << " accounts: " << dump.accounts.size();
    return out;
}

void to_json(nlohmann::json& json, const DumpAccounts& dump) {
    nlohmann::json accounts({});

    for (const auto& entry : dump.accounts) {
        nlohmann::json item;
        to_json(item, entry.second);
        accounts.push_back(nlohmann::json::object_t::value_type(address_to_hex(entry.first), item));
    }
    auto encoded = base64_encode({dump.next.bytes, kAddressLength}, false);
    json = {
        {"root", dump.root},
        {"accounts", accounts},
        {"next", encoded}};
}

void to_json(nlohmann::json& json, const DumpAccount& dump_account) {
    json["balance"] = to_string(dump_account.balance);
    json["nonce"] = dump_account.nonce;
    json["root"] = dump_account.root;
    json["codeHash"] = dump_account.code_hash;
    if (dump_account.code) {
        json["code"] = silkworm::to_hex(dump_account.code.value(), /*with_prefix=*/true);
    }
    if (dump_account.storage) {
        nlohmann::json storage({});
        for (const auto& entry : dump_account.storage.value()) {
            storage[silkworm::to_hex(entry.first, /*with_prefix=*/true)] = silkworm::to_hex(entry.second);
        }
        json["storage"] = storage;
    }
}

}  // namespace silkworm::rpc
