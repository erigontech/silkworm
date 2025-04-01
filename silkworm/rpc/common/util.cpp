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

#include "util.hpp"

#include <evmone/instructions_traits.hpp>

#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

std::ostream& operator<<(std::ostream& out, const Account& account) {
    out << account.to_string();
    return out;
}

static const char* kBase64Chars[2] = {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "+/",

    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "-_"};

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
    const size_t len = bytes_to_encode.size();
    const size_t len_encoded = (len + 2) / 3 * 4;

    char trailing_char = url ? '.' : '=';
    const char* base64_chars = kBase64Chars[url ? 1 : 0];

    std::string ret;
    ret.reserve(len_encoded);

    unsigned int pos = 0;
    while (pos < len) {
        ret.push_back(base64_chars[(bytes_to_encode[pos + 0] & 0xfc) >> 2]);

        if (pos + 1 < len) {
            ret.push_back(base64_chars[((bytes_to_encode[pos + 0] & 0x03) << 4) + ((bytes_to_encode[pos + 1] & 0xf0) >> 4)]);

            if (pos + 2 < len) {
                ret.push_back(base64_chars[((bytes_to_encode[pos + 1] & 0x0f) << 2) + ((bytes_to_encode[pos + 2] & 0xc0) >> 6)]);
                ret.push_back(base64_chars[bytes_to_encode[pos + 2] & 0x3f]);
            } else {
                ret.push_back(base64_chars[(bytes_to_encode[pos + 1] & 0x0f) << 2]);
                ret.push_back(trailing_char);
            }
        } else {
            ret.push_back(base64_chars[(bytes_to_encode[pos + 0] & 0x03) << 4]);
            ret.push_back(trailing_char);
            ret.push_back(trailing_char);
        }

        pos += 3;
    }

    return ret;
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
    static constexpr const char* kHexDigits = "0123456789abcdef";
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
