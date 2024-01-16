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

#pragma once

#include <intx/intx.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/decoding_result.hpp>
#include <silkworm/core/common/empty_hashes.hpp>

namespace silkworm {

// Default incarnation for smart contracts is 1;
// contracts that were previously destructed and then re-created will have an incarnation greater than 1.
// The incarnation of non-contracts (externally owned accounts) is always 0.
inline constexpr uint64_t kDefaultIncarnation{1};

struct Account {
    uint64_t nonce{0};
    intx::uint256 balance;
    evmc::bytes32 code_hash{kEmptyHash};
    uint64_t incarnation{0};
    uint64_t previous_incarnation{0};

    //! \remarks Erigon's (*Account)EncodeForStorage
    [[nodiscard]] Bytes encode_for_storage(bool omit_code_hash = false) const;

    //! \remarks Erigon's (*Account)EncodingLengthForStorage
    [[nodiscard]] size_t encoding_length_for_storage() const;

    //! \brief Rlp encodes Account
    [[nodiscard]] Bytes rlp(const evmc::bytes32& storage_root) const;

    //! \brief Returns an Account from it's encoded representation
    [[nodiscard]] static tl::expected<Account, DecodingError> from_encoded_storage(ByteView encoded_payload) noexcept;

    //! \brief Returns an Account Incarnation from it's encoded representation
    //! \remarks Similar to from_encoded_storage but faster as it parses only incarnation
    [[nodiscard]] static tl::expected<uint64_t, DecodingError> incarnation_from_encoded_storage(
        ByteView encoded_payload) noexcept;

    friend bool operator==(const Account&, const Account&) = default;
};

}  // namespace silkworm
