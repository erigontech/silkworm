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

#include "transaction.hpp"

#include <iomanip>
#include <sstream>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {
intx::uint256 Transaction::effective_gas_price() const {
    return silkworm::Transaction::effective_gas_price(block_base_fee_per_gas.value_or(0));
}

std::ostream& operator<<(std::ostream& out, const Transaction& t) {
    out << t.to_string();
    return out;
}

std::string Transaction::to_string() const {
    const auto& t = *this;
    std::stringstream out;

    out << " #access_list: " << t.access_list.size();
    out << " #authorizations: " << t.authorizations.size();
    out << " block_hash: " << to_hex(t.block_hash);
    out << " block_num: " << t.block_num;
    out << " block_base_fee_per_gas: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.block_base_fee_per_gas.value_or(0)));
    if (t.chain_id) {
        out << " chain_id: " << silkworm::to_hex(silkworm::endian::to_big_compact(*t.chain_id));
    } else {
        out << " chain_id: null";
    }
    out << " data: " << silkworm::to_hex(t.data);
    if (t.sender()) {
        out << " from: " << *t.sender();
    } else {
        out << " from: null";
    }
    out << " nonce: " << t.nonce;
    out << " max_priority_fee_per_gas: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.max_priority_fee_per_gas));
    out << " max_fee_per_gas: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.max_fee_per_gas));
    out << " gas_price: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.effective_gas_price()));
    out << " gas_limit: " << t.gas_limit;
    out << " odd_y_parity: " << t.odd_y_parity;

    out << " r: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.r));
    out << " s: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.s));

    if (t.to) {
        out << " to: " << *t.to;
    } else {
        out << " to: null";
    }
    out << " transaction_index: " << t.transaction_index;
    out << " type: 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(t.type);
    out << " value: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.value));
    out << std::dec;
    return out.str();
}

std::string core_transaction_to_string(const silkworm::Transaction& t) {
    std::stringstream out;

    out << " #access_list: " << t.access_list.size();
    out << " #authorizations: " << t.authorizations.size();
    if (t.chain_id) {
        out << " chain_id: " << silkworm::to_hex(silkworm::endian::to_big_compact(*t.chain_id));
    } else {
        out << " chain_id: null";
    }
    out << " data: " << silkworm::to_hex(t.data);
    if (t.sender()) {
        out << " from: " << *t.sender();
    } else {
        out << " from: null";
    }
    out << " nonce: " << t.nonce;
    out << " max_priority_fee_per_gas: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.max_priority_fee_per_gas));
    out << " max_fee_per_gas: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.max_fee_per_gas));
    out << " gas_limit: " << t.gas_limit;
    out << " odd_y_parity: " << t.odd_y_parity;

    out << " r: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.r));
    out << " s: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.s));

    if (t.to) {
        out << " to: " << *t.to;
    } else {
        out << " to: null";
    }
    out << " type: 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(t.type) << std::dec;
    out << " value: " << silkworm::to_hex(silkworm::endian::to_big_compact(t.value));

    return out.str();
}

std::ostream& operator<<(std::ostream& out, const silkworm::Transaction& t) {
    out << core_transaction_to_string(t);
    return out;
}

}  // namespace silkworm::rpc
