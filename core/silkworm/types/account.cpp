/*
   Copyright 2020-2021 The Silkworm Authors

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

std::pair<uint64_t, rlp::DecodingResult> extract_incarnation(ByteView encoded) {
    uint8_t field_set = encoded[0];
    size_t pos{1};

    if (field_set & 1) {
        pos += encoded[pos++];
    }
    if (field_set & 2) {
        pos += encoded[pos++];
    }
    if (field_set & 4) {
        // Incarnation has been found.
        uint8_t len = encoded[pos++];
        const std::optional<uint64_t> incarnation{endian::from_big_compact<uint64_t>(encoded.substr(pos, len))};
        if (incarnation == std::nullopt) {
            return {0, rlp::DecodingResult::kOverflow};
        }
        return {*incarnation, rlp::DecodingResult::kOk};
    }
    return {0, rlp::DecodingResult::kOk};
}

std::pair<Account, rlp::DecodingResult> decode_account_from_storage(ByteView encoded) noexcept {
    Account a{};
    if (encoded.empty()) {
        return {a, rlp::DecodingResult::kOk};
    }

    uint8_t field_set = encoded[0];
    size_t pos{1};

    if (field_set & 1) {
        uint8_t len = encoded[pos++];
        if (encoded.length() < pos + len) {
            return {a, rlp::DecodingResult::kInputTooShort};
        }
        const std::optional<uint64_t> nonce{endian::from_big_compact<uint64_t>(encoded.substr(pos, len))};
        if (nonce == std::nullopt) {
            return {a, rlp::DecodingResult::kOverflow};
        }
        a.nonce = *nonce;
        pos += len;
    }

    if (field_set & 2) {
        uint8_t len = encoded[pos++];
        if (encoded.length() < pos + len) {
            return {a, rlp::DecodingResult::kInputTooShort};
        }
        std::memcpy(&as_bytes(a.balance)[32 - len], &encoded[pos], len);
        a.balance = bswap(a.balance);
        pos += len;
    }

    if (field_set & 4) {
        uint8_t len = encoded[pos++];
        if (encoded.length() < pos + len) {
            return {a, rlp::DecodingResult::kInputTooShort};
        }
        const std::optional<uint64_t> incarnation{endian::from_big_compact<uint64_t>(encoded.substr(pos, len))};
        if (incarnation == std::nullopt) {
            return {a, rlp::DecodingResult::kOverflow};
        }
        a.incarnation = *incarnation;
        pos += len;
    }

    if (field_set & 8) {
        uint8_t len = encoded[pos++];
        if (len != kHashLength) {
            return {a, rlp::DecodingResult::kUnexpectedLength};
        }
        if (encoded.length() < pos + len) {
            return {a, rlp::DecodingResult::kInputTooShort};
        }
        std::memcpy(a.code_hash.bytes, &encoded[pos], kHashLength);
    }

    return {a, rlp::DecodingResult::kOk};
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
