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

#include "account.hpp"

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

Bytes Account::encode_for_storage(bool omit_code_hash) const {
    Bytes res(1, '\0');
    uint8_t field_set{0};

    if (nonce != 0) {
        field_set |= 1;
        auto be{endian::to_big_compact(nonce)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (balance != 0) {
        field_set |= 2;
        auto be{endian::to_big_compact(balance)};
        res.push_back(static_cast<uint8_t>(be.length()));
        res.append(be);
    }

    if (incarnation != 0) {
        field_set |= 4;
        auto be{endian::to_big_compact(incarnation)};
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
        auto be{endian::to_big_compact(nonce)};
        len += 1 + be.length();
    }

    if (balance != 0) {
        auto be{endian::to_big_compact(balance)};
        len += 1 + be.length();
    }

    if (incarnation != 0) {
        auto be{endian::to_big_compact(incarnation)};
        len += 1 + be.length();
    }

    if (code_hash != kEmptyHash) {
        len += 1 + kHashLength;
    }

    return len;
}

static inline tl::expected<uint8_t, DecodingError> validate_encoded_head(ByteView& encoded_payload) noexcept {
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

tl::expected<Account, DecodingError> Account::from_encoded_storage(ByteView encoded_payload) noexcept {
    Account a;
    const tl::expected<uint8_t, DecodingError> field_set{validate_encoded_head(encoded_payload)};
    if (!field_set) {
        return tl::unexpected{field_set.error()};
    } else if (field_set == 0) {
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

tl::expected<Account, DecodingError> Account::from_encoded_storage_v3(ByteView encoded_payload) noexcept {
    Account a;
    if (encoded_payload.empty()) {
        return a;
    }
    size_t pos{0};
    for (int i{0}; i < 4; ++i) {
        uint8_t len = encoded_payload[pos++];
        if (len == 0) {
            if (encoded_payload.length() == pos && i < 3) {
                return tl::unexpected{DecodingError::kUnexpectedLength};
            }
            continue;
        }
        if (encoded_payload.length() < pos + len) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }
        const auto encoded_value{encoded_payload.substr(pos, len)};
        switch (i) {
            case 0:
                if (DecodingResult res{endian::from_big_compact(encoded_value, a.nonce)}; !res) {
                    return tl::unexpected{res.error()};
                }
                break;
            case 1:
                if (DecodingResult res{endian::from_big_compact(encoded_value, a.balance)}; !res) {
                    return tl::unexpected{res.error()};
                }
                break;
            case 2:
                if (len != kHashLength) {
                    return tl::unexpected{DecodingError::kUnexpectedLength};
                }
                std::memcpy(a.code_hash.bytes, encoded_value.data(), kHashLength);
                break;
            case 3:
                if (DecodingResult res{endian::from_big_compact(encoded_value, a.incarnation)}; !res) {
                    return tl::unexpected{res.error()};
                }
                break;
            default:
                intx::unreachable();
        }
        pos += len;
    }

    return a;
}

tl::expected<uint64_t, DecodingError> Account::incarnation_from_encoded_storage(ByteView encoded_payload) noexcept {
    const tl::expected<uint8_t, DecodingError> field_set{validate_encoded_head(encoded_payload)};
    if (!field_set) {
        return tl::unexpected{field_set.error()};
    } else if (!(*field_set & /*incarnation mask*/ 4)) {
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

}  // namespace silkworm
