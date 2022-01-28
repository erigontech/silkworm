/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "account.hpp"

#include <silkworm/common/endian.hpp>

namespace silkworm {

bool operator==(const Account& a, const Account& b) {
    return a.nonce == b.nonce && a.balance == b.balance && a.code_hash == b.code_hash && a.incarnation == b.incarnation;
}

Bytes Account::encode_for_storage(bool omit_code_hash) const {
    Bytes res(1, '\0');
    uint8_t field_set{0};

    if (nonce != 0) {
        field_set |= 1;
        const Bytes be{endian::to_big_compact(nonce)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (balance != 0) {
        field_set |= 2;
        const Bytes be{endian::to_big_compact(balance)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (incarnation != 0) {
        field_set |= 4;
        const Bytes be{endian::to_big_compact(incarnation)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (code_hash != kEmptyHash && !omit_code_hash) {
        field_set |= 8;
        res.push_back(kHashLength);
        res.append(code_hash.bytes, kHashLength);
    }

    res[0] = field_set;
    return res;
}

size_t Account::encoding_length_for_storage() const {
    size_t len{1};

    if (nonce != 0) {
        const Bytes be{endian::to_big_compact(nonce)};
        len += 1 + be.length();
    }

    if (balance != 0) {
        const Bytes be{endian::to_big_compact(balance)};
        len += 1 + be.length();
    }

    if (incarnation != 0) {
        const Bytes be{endian::to_big_compact(incarnation)};
        len += 1 + be.length();
    }

    if (code_hash != kEmptyHash) {
        len += 1 + kHashLength;
    }

    return len;
}

std::pair<Account, rlp::DecodingResult> Account::from_encoded_storage(ByteView encoded_payload) noexcept {
    Account a{};
    if (encoded_payload.empty()) {
        return {a, rlp::DecodingResult::kOk};
    } else if (encoded_payload[0] && encoded_payload.length() == 1) {
        // Must be at least 2 bytes : field_set + len of payload
        return {a, rlp::DecodingResult::kInputTooShort};
    }

    uint8_t field_set = encoded_payload[0];
    size_t pos{1};

    for (int i{1}; i < 16; i *= 2) {
        if (field_set & i) {
            uint8_t len = encoded_payload[pos++];
            if (encoded_payload.length() < pos + len) {
                return {a, rlp::DecodingResult::kInputTooShort};
            }
            switch (i) {
                case 1: {
                    const std::optional<uint64_t> nonce{endian::from_big_compact<uint64_t>(encoded_payload.substr(pos, len))};
                    if (nonce == std::nullopt) {
                        return {a, rlp::DecodingResult::kLeadingZero};
                    }
                    a.nonce = *nonce;
                } break;
                case 2:
                    std::memcpy(&as_bytes(a.balance)[32 - len], &encoded_payload[pos], len);
                    a.balance = bswap(a.balance);
                    break;
                case 4: {
                    const std::optional<uint64_t> incarnation{
                        endian::from_big_compact<uint64_t>(encoded_payload.substr(pos, len))};
                    if (incarnation == std::nullopt) {
                        return {a, rlp::DecodingResult::kLeadingZero};
                    }
                    a.incarnation = *incarnation;
                } break;
                case 8:
                    if (len != kHashLength) {
                        return {a, rlp::DecodingResult::kUnexpectedLength};
                    }
                    std::memcpy(a.code_hash.bytes, &encoded_payload[pos], kHashLength);
                    break;
                default:
                    len = 0;
            }
            pos += len;
        }
    }

    return {a, rlp::DecodingResult::kOk};
}

std::pair<uint64_t, rlp::DecodingResult> Account::incarnation_from_encoded_storage(ByteView encoded_payload) noexcept {
    if (encoded_payload.empty()) {
        return {0, rlp::DecodingResult::kOk};
    } else if (encoded_payload[0] && encoded_payload.length() == 1) {
        // Must be at least 2 bytes : field_set + len of payload
        return {0, rlp::DecodingResult::kInputTooShort};
    }

    uint8_t field_set = encoded_payload[0];
    size_t pos{1};

    for (int i{1}; i < 8; i *= 2) {
        if (field_set & i) {
            uint8_t len = encoded_payload[pos++];
            if (encoded_payload.length() < pos + len) {
                return {0, rlp::DecodingResult::kInputTooShort};
            }
            switch (i) {
                case 1:
                case 2:
                    break;
                case 4: {
                    const std::optional<uint64_t> incarnation{
                        endian::from_big_compact<uint64_t>(encoded_payload.substr(pos, len))};
                    if (incarnation == std::nullopt) {
                        return {0, rlp::DecodingResult::kLeadingZero};
                    }
                    return {*incarnation, rlp::DecodingResult::kOk};
                } break;
                default:
                    len = 0;
            }
            pos += len;
        }
    }
    return {0, rlp::DecodingResult::kOk};
}

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
    rlp::encode(to, storage_root.bytes);
    rlp::encode(to, code_hash.bytes);

    return to;
}

}  // namespace silkworm
