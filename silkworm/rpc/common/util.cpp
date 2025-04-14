// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "util.hpp"

#include <base64.h>

#include <evmone/instructions_traits.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

std::ostream& operator<<(std::ostream& out, const Account& account) {
    out << account.to_string();
    return out;
}

void increment(Bytes& array) {
    for (auto& it : std::ranges::reverse_view(array)) {
        if (it < 0xFF) {
            ++it;
            break;
        }
        it = 0x00;
    }
}

std::string base64_encode(ByteView bytes_to_encode, bool url) {
    return ::base64_encode(byte_view_to_string_view(bytes_to_encode), url);
}

// check whether the fee of the given transaction is reasonable (under the cap)
bool check_tx_fee_less_cap(float cap, const intx::uint256& max_fee_per_gas, uint64_t gas_limit) {
    // Short circuit if there is no cap for transaction fee at all
    if (cap == 0) {
        return true;
    }
    float fee_eth = (to_float(max_fee_per_gas) * static_cast<float>(gas_limit)) / static_cast<float>(silkworm::kEther);
    return fee_eth <= cap;
}

bool is_replay_protected(const silkworm::Transaction& txn) {
    if (txn.type != TransactionType::kLegacy) {
        return true;
    }
    intx::uint256 v = txn.v();
    return v != 27 && v != 28 && v != 0 && v != 1;
}

std::string decoding_result_to_string(silkworm::DecodingError decode_result) {
    switch (decode_result) {
        case silkworm::DecodingError::kOverflow:
            return "rlp: uint overflow";
        case silkworm::DecodingError::kLeadingZero:
            return "rlp: leading Zero";
        case silkworm::DecodingError::kInputTooShort:
            return "rlp: value size exceeds available input length";
        case silkworm::DecodingError::kInputTooLong:
            return "rlp: input exceeds encoded length";
        case silkworm::DecodingError::kNonCanonicalSize:
            return "rlp: non-canonical size information";
        case silkworm::DecodingError::kUnexpectedLength:
            return "rlp: unexpected Length";
        case silkworm::DecodingError::kUnexpectedString:
            return "rlp: expected list, got string instead";
        case silkworm::DecodingError::kUnexpectedList:
            return "rlp: expected string, got list instead";
        case silkworm::DecodingError::kUnexpectedListElements:
            return "rlp: unexpected list element(s)";
        case silkworm::DecodingError::kInvalidVInSignature:  // v != 27 && v != 28 && v < 35, see EIP-155
            return "rlp: invalid V in signature";
        case silkworm::DecodingError::kUnsupportedTransactionType:
            return "rlp: unknown tx type prefix";
        case silkworm::DecodingError::kInvalidFieldset:
            return "rlp: invalid field set";
        case silkworm::DecodingError::kUnexpectedEip2718Serialization:
            return "rlp: unexpected EIP-2178 serialization";
        case silkworm::DecodingError::kInvalidHashesLength:
            return "rlp: invalid hashes length";
        case silkworm::DecodingError::kInvalidMasksSubsets:
            return "rlp: invalid masks subsets";
        default:
            return "rlp: unknown error [" + std::to_string(static_cast<int>(decode_result)) + "]";
    }
}

const silkworm::ChainConfig* lookup_chain_config(uint64_t chain_id) {
    // TODO(canepat) we should read chain config from db
    const auto chain_config = kKnownChainConfigs.find(chain_id);
    if (!chain_config) {
        throw std::runtime_error{"unknown chain ID: " + std::to_string(chain_id)};
    }
    return *chain_config;
}

std::string get_opcode_hex(uint8_t opcode) {
    static constexpr std::string_view kHexDigits = "0123456789abcdef";
    if (opcode < 16) {
        return {'0', 'x', kHexDigits[opcode]};
    }
    return {'0', 'x', kHexDigits[opcode >> 4], kHexDigits[opcode & 0xf]};
}

std::optional<std::string_view> get_opcode_name(std::uint8_t opcode) noexcept {
    // TODO(evmone): evmone can provide a function like this directly with optimized lookup table.
    const auto& tr = evmone::instr::traits[opcode];
    if (!tr.since.has_value())
        return std::nullopt;
    if (opcode == evmone::OP_PREVRANDAO)
        return "DIFFICULTY";  // Overwrite for compatibility with Erigon and Geth.
    return tr.name;
}

}  // namespace silkworm
