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

#include <silkworm/common/util.hpp>

namespace silkworm {

bool operator==(const Account& a, const Account& b) {
    // Intentionally omit storage_root
    return a.nonce == b.nonce && a.balance == b.balance && a.code_hash == b.code_hash && a.incarnation == b.incarnation;
}

Bytes Account::encode_for_storage(bool omit_code_hash) const {
    Bytes res(1, '\0');
    uint8_t field_set{0};

    if (nonce != 0) {
        field_set |= 1;
        ByteView be{rlp::big_endian(nonce)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (balance != 0) {
        field_set |= 2;
        ByteView be{rlp::big_endian(balance)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (incarnation != 0) {
        field_set |= 4;
        ByteView be{rlp::big_endian(incarnation)};
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
        ByteView be{rlp::big_endian(nonce)};
        len += 1 + be.length();
    }

    if (balance != 0) {
        ByteView be{rlp::big_endian(balance)};
        len += 1 + be.length();
    }

    if (incarnation != 0) {
        ByteView be{rlp::big_endian(incarnation)};
        len += 1 + be.length();
    }

    if (code_hash != kEmptyHash) {
        len += 1 + kHashLength;
    }

    return len;
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
        auto [nonce, err]{rlp::read_uint64(encoded.substr(pos, len))};
        if (err != rlp::DecodingResult::kOk) {
            return {a, err};
        }
        a.nonce = nonce;
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
        auto [incarnation, err]{rlp::read_uint64(encoded.substr(pos, len))};
        if (err != rlp::DecodingResult::kOk) {
            return {a, err};
        }
        a.incarnation = incarnation;
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

namespace rlp {

    void encode(Bytes& to, const Account& account) {
        Header h{true, 0};
        h.payload_length += length(account.nonce);
        h.payload_length += length(account.balance);
        h.payload_length += kHashLength + 1;
        h.payload_length += kHashLength + 1;

        encode_header(to, h);
        encode(to, account.nonce);
        encode(to, account.balance);
        encode(to, account.storage_root.bytes);
        encode(to, account.code_hash.bytes);
    }

    template <>
    DecodingResult decode(ByteView& from, Account& to) noexcept {
        auto [h, err]{decode_header(from)};
        if (err != DecodingResult::kOk) {
            return err;
        }
        if (!h.list) {
            return DecodingResult::kUnexpectedString;
        }
        uint64_t leftover{from.length() - h.payload_length};

        if (DecodingResult err{decode(from, to.nonce)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.balance)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.storage_root.bytes)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.code_hash.bytes)}; err != DecodingResult::kOk) {
            return err;
        }

        return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
    }

}  // namespace rlp
}  // namespace silkworm
