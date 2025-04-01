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

#include "call.hpp"

#include <sstream>
#include <string>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

static std::string optional_uint256_to_string(const std::optional<intx::uint256>& u) {
    return silkworm::to_hex(silkworm::endian::to_big_compact(u.value_or(intx::uint256{})));
}

static std::string optional_bytes_to_string(const std::optional<silkworm::Bytes>& u) {
    return silkworm::to_hex(u.value_or(silkworm::Bytes{}));
}

std::ostream& operator<<(std::ostream& out, const Call& call) {
    out << call.to_string();
    return out;
}

std::string Call::to_string() const {
    const auto& call = *this;
    std::stringstream out;
    out << "from: " << call.from.value_or(evmc::address{}) << " "
        << "to: " << call.to.value_or(evmc::address{}) << " "
        << "gas: " << call.gas.value_or(0) << " "
        << "gas_price: " << optional_uint256_to_string(call.gas_price) << " "
        << "max_priority_fee_per_gas: " << optional_uint256_to_string(call.max_priority_fee_per_gas) << " "
        << "max_fee_per_gas: " << optional_uint256_to_string(call.max_fee_per_gas) << " "
        << "value: " << optional_uint256_to_string(call.value) << " "
        << "data: " << optional_bytes_to_string(call.data);
    return out.str();
}

std::string bundles_to_string(const Bundles& bundles) {
    std::stringstream out;
    out << "[";
    bool first = true;
    for (const auto& bundle : bundles) {
        if (!first) {
            out << ", ";
        }
        out << "{" << bundle << "}";
        first = false;
    }
    out << "]";
    return out.str();
}

std::ostream& operator<<(std::ostream& out, const Bundles& bundles) {
    out << bundles_to_string(bundles);
    return out;
}

std::ostream& operator<<(std::ostream& out, const Bundle& bundle) {
    out << bundle.to_string();
    return out;
}

std::string Bundle::to_string() const {
    const auto& bundle = *this;
    std::stringstream out;

    out << "transactions: [";
    for (const auto& transaction : bundle.transactions) {
        out << transaction;
    }
    out << "] ";
    out << "block_override: " << bundle.block_override;
    return out.str();
}

std::ostream& operator<<(std::ostream& out, const BlockOverrides& bo) {
    out << bo.to_string();
    return out;
}

std::string BlockOverrides::to_string() const {
    const auto& bo = *this;
    std::stringstream out;

    out << "block_num: " << bo.block_num.value_or(0) << " ";
    return out.str();
}

std::ostream& operator<<(std::ostream& out, const SimulationContext& sc) {
    out << sc.to_string();
    return out;
}

std::string SimulationContext::to_string() const {
    const auto& sc = *this;
    std::stringstream out;

    out << "block_num: " << sc.block_num << " "
        << "transaction_index: " << sc.transaction_index;
    return out.str();
}

std::string accounts_overrides_to_string(const AccountsOverrides& ao) {
    std::stringstream out;
    out << "{";
    bool first = true;
    for (const auto& item : ao) {
        if (!first) {
            out << ", ";
        }
        out << item.first << ": {" << item.second << "}";
        first = false;
    }
    out << "} ";
    return out.str();
}

std::ostream& operator<<(std::ostream& out, const AccountsOverrides& ao) {
    out << accounts_overrides_to_string(ao);
    return out;
}

std::ostream& operator<<(std::ostream& out, const AccountOverrides& ao) {
    out << ao.to_string();
    return out;
}

std::string AccountOverrides::to_string() const {
    const auto& ao = *this;
    std::stringstream out;

    out << "balance: " << optional_uint256_to_string(ao.balance) << " "
        << "nonce: " << ao.nonce.value_or(0) << " "
        << "code: " << optional_bytes_to_string(ao.code) << " "
        << "state: #" << ao.state.size() << " "
        << "state_diff: #" << ao.state_diff.size() << " ";
    return out.str();
}

}  // namespace silkworm::rpc
