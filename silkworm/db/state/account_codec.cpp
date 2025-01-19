/*
   Copyright 2022 The Silkworm Authors

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

#include "account_codec.hpp"

#include <silkworm/core/common/endian.hpp>

namespace silkworm::db::state {

Bytes AccountCodec::encode_for_storage(const Account& account, bool omit_code_hash) {
    Bytes res(1, '\0');
    uint8_t field_set{0};

    if (account.nonce != 0) {
        field_set |= 1;
        auto be{endian::to_big_compact(account.nonce)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (account.balance != 0) {
        field_set |= 2;
        auto be{endian::to_big_compact(account.balance)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (account.incarnation != 0) {
        field_set |= 4;
        auto be{endian::to_big_compact(account.incarnation)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (account.code_hash != kEmptyHash && !omit_code_hash) {
        field_set |= 8;
        res.push_back(kHashLength);
        res.append(account.code_hash.bytes, kHashLength);
    }

    res[0] = field_set;
    return res;
}

size_t AccountCodec::encoding_length_for_storage(const Account& account) {
    size_t len{1};

    if (account.nonce != 0) {
        auto be{endian::to_big_compact(account.nonce)};
        len += 1 + be.length();
    }

    if (account.balance != 0) {
        auto be{endian::to_big_compact(account.balance)};
        len += 1 + be.length();
    }

    if (account.incarnation != 0) {
        auto be{endian::to_big_compact(account.incarnation)};
        len += 1 + be.length();
    }

    if (account.code_hash != kEmptyHash) {
        len += 1 + kHashLength;
    }

    return len;
}

static tl::expected<uint8_t, DecodingError> validate_encoded_head(ByteView& encoded_payload) noexcept {
    if (encoded_payload.empty()) {
        return 0;
    }
    if (encoded_payload[0] && encoded_payload.length() == 1) {
        // Must be at least 2 bytes : field_set + len of payload
        return tl::unexpected{DecodingError::kInputTooShort};
    }
    if (encoded_payload[0] > 15) {
        // Can only be at max 1 | 2 | 4 | 8
        return tl::unexpected{DecodingError::kInvalidFieldset};
    }

    return encoded_payload[0];
}

tl::expected<Account, DecodingError> AccountCodec::from_encoded_storage(ByteView encoded_payload) noexcept {
    const tl::expected<uint8_t, DecodingError> field_set{validate_encoded_head(encoded_payload)};
    if (!field_set) {
        return tl::unexpected{field_set.error()};
    }
    Account a;
    if (field_set == 0) {
        return a;
    }

    size_t pos{1};
    for (int i{1}; i < 16; i *= 2) {
        if (*field_set & i) {
            uint8_t len = encoded_payload[pos++];
            if (encoded_payload.length() < pos + len) {
                return tl::unexpected{DecodingError::kInputTooShort};
            }
            const auto encoded_value{encoded_payload.substr(pos, len)};
            switch (i) {
                case 1:
                    if (DecodingResult res{endian::from_big_compact(encoded_value, a.nonce)}; !res) {
                        return tl::unexpected{res.error()};
                    }
                    break;
                case 2:
                    if (DecodingResult res{endian::from_big_compact(encoded_value, a.balance)}; !res) {
                        return tl::unexpected{res.error()};
                    }
                    break;
                case 4:
                    if (DecodingResult res{endian::from_big_compact(encoded_value, a.incarnation)}; !res) {
                        return tl::unexpected{res.error()};
                    }
                    break;
                case 8:
                    if (len != kHashLength) {
                        return tl::unexpected{DecodingError::kUnexpectedLength};
                    }
                    std::memcpy(a.code_hash.bytes, &encoded_value[0], kHashLength);
                    break;
                default:
                    intx::unreachable();
            }
            pos += len;
        }
    }

    return a;
}

Bytes AccountCodec::encode_for_storage_v3(const Account& account) {
    Bytes result;
    auto write = [&result](ByteView field) {
        result.push_back(static_cast<uint8_t>(field.size()));
        result.append(field);
    };

    write(endian::to_big_compact(account.nonce));
    write(endian::to_big_compact(account.balance));
    write((account.code_hash != kEmptyHash) ? ByteView{account.code_hash.bytes, kHashLength} : ByteView{});
    write(endian::to_big_compact(account.incarnation));

    return result;
}

tl::expected<Account, DecodingError> AccountCodec::from_encoded_storage_v3(ByteView encoded_payload) noexcept {
    auto read = [&encoded_payload]() -> tl::expected<ByteView, DecodingError> {
        if (encoded_payload.empty()) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }
        uint8_t len = encoded_payload[0];
        encoded_payload.remove_prefix(1);

        if (encoded_payload.size() < len) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }
        ByteView field = encoded_payload.substr(0, len);
        encoded_payload.remove_prefix(len);
        return field;
    };

    auto read_and_decode = [&read](auto out_ptr, auto decode) -> DecodingResult {
        auto field = read();
        if (!field) return tl::unexpected{field.error()};
        if (field->empty()) return {};
        return decode(*field, *out_ptr);
    };

    auto decode_hash = [](ByteView data, evmc_bytes32& out_hash) -> DecodingResult {
        if (data.size() == kHashLength) {
            std::memcpy(out_hash.bytes, data.data(), kHashLength);
            return {};
        }
        return tl::unexpected{DecodingError::kUnexpectedLength};
    };

    Account account;

    auto result = read_and_decode(&account.nonce, endian::from_big_compact<uint64_t>);
    if (!result) return tl::unexpected{result.error()};

    result = read_and_decode(&account.balance, endian::from_big_compact<intx::uint256>);
    if (!result) return tl::unexpected{result.error()};

    result = read_and_decode(&account.code_hash, decode_hash);
    if (!result) return tl::unexpected{result.error()};

    result = read_and_decode(&account.incarnation, endian::from_big_compact<uint64_t>);
    if (!result) return tl::unexpected{result.error()};

    return account;
}

tl::expected<uint64_t, DecodingError> AccountCodec::incarnation_from_encoded_storage(ByteView encoded_payload) noexcept {
    const tl::expected<uint8_t, DecodingError> field_set{validate_encoded_head(encoded_payload)};
    if (!field_set) {
        return tl::unexpected{field_set.error()};
    }
    if (!(*field_set & /*incarnation mask*/ 4)) {
        return 0;
    }

    size_t pos{1};
    uint64_t incarnation{0};
    for (int i{1}; i < 8; i *= 2) {
        if (*field_set & i) {
            uint8_t len = encoded_payload[pos++];
            if (encoded_payload.length() < pos + len) {
                return tl::unexpected{DecodingError::kInputTooShort};
            }
            switch (i) {
                case 1:
                case 2:
                    break;
                case 4:
                    if (DecodingResult res{endian::from_big_compact(encoded_payload.substr(pos, len), incarnation)}; !res) {
                        return tl::unexpected{res.error()};
                    }
                    return incarnation;
                default:
                    intx::unreachable();
            }
            pos += len;
        }
    }
    intx::unreachable();
}

}  // namespace silkworm::db::state
