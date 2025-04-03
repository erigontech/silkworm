// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "account.hpp"

#include <sstream>

#include <silkworm/core/rlp/encode.hpp>

namespace silkworm {

Bytes Account::rlp(const evmc::bytes32& storage_root) const {
    rlp::Header h{true, 0};
    h.payload_length += rlp::length(nonce);
    h.payload_length += rlp::length(balance);
    h.payload_length += kHashLength + 1;
    h.payload_length += kHashLength + 1;

    Bytes to;

    rlp::encode_header(to, h);
    rlp::encode(to, nonce);
    rlp::encode(to, balance);
    rlp::encode(to, storage_root);
    rlp::encode(to, code_hash);

    return to;
}

std::string Account::to_string() const {
    const auto& account = *this;
    std::stringstream out;

    out << "nonce: " << account.nonce;
    out << " balance: "
        << "0x" << intx::hex(account.balance);
    out << " code_hash: 0x" << to_hex(account.code_hash);
    out << " incarnation: " << account.incarnation;
    return out.str();
}

}  // namespace silkworm
