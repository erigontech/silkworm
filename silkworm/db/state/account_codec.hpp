// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/decoding_result.hpp>
#include <silkworm/core/types/account.hpp>

namespace silkworm::db::state {

struct AccountCodec {
    //! \brief Encode the account into its binary representation for data storage
    //! \remarks Erigon (*Account)EncodeForStorage
    static Bytes encode_for_storage(const Account& account, bool omit_code_hash = false);

    //! \brief Compute the length of the account binary representation for data storage
    //! \remarks Erigon (*Account)EncodingLengthForStorage
    static size_t encoding_length_for_storage(const Account& account);

    //! \brief Decode an Account from its binary representation for data storage
    static tl::expected<Account, DecodingError> from_encoded_storage(ByteView encoded_payload) noexcept;

    //! \brief Encode the account into its binary representation for data storage in E3 data format
    static Bytes encode_for_storage_v3(const Account& account);

    //! \brief Decode an Account from its binary representation for data storage in E3 data format
    static tl::expected<Account, DecodingError> from_encoded_storage_v3(ByteView encoded_payload) noexcept;

    //! \brief Return an Account Incarnation from its binary representation for data storage
    //! \remarks Similar to from_encoded_storage but faster as it parses only incarnation
    static tl::expected<uint64_t, DecodingError> incarnation_from_encoded_storage(
        ByteView encoded_payload) noexcept;
};

struct AccountEncodable : public Account {
    Bytes encode_for_storage(bool omit_code_hash = false) const {
        return AccountCodec::encode_for_storage(*this, omit_code_hash);
    }
    size_t encoding_length_for_storage() const {
        return AccountCodec::encoding_length_for_storage(*this);
    }
};

}  // namespace silkworm::db::state
