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

#ifndef SILKWORM_TYPES_ACCOUNT_HPP_
#define SILKWORM_TYPES_ACCOUNT_HPP_

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/rlp/decode.hpp>

namespace silkworm {

// Default incarnation for smart contracts is 1;
// contracts that were previously destructed and then re-created will have an incarnation greater than 1.
// The incarnation of non-contracts (externally owned accounts) is always 0.
constexpr uint64_t kDefaultIncarnation{1};

struct Account {
    uint64_t nonce{0};
    intx::uint256 balance;
    evmc::bytes32 code_hash{kEmptyHash};
    uint64_t incarnation{0};

    // Erigon (*Account)EncodeForStorage
    Bytes encode_for_storage(bool omit_code_hash = false) const;

    // Erigon (*Account)EncodingLengthForStorage
    size_t encoding_length_for_storage() const;

    Bytes rlp(const evmc::bytes32& storage_root) const;
};

bool operator==(const Account& a, const Account& b);

 /*
 * Extract the incarnation from an encoded account object without fully decoding it.
 */
std::pair<uint64_t, rlp::DecodingResult> extract_incarnation(ByteView);

// Erigon (*Account)DecodeForStorage
[[nodiscard]] std::pair<Account, rlp::DecodingResult> decode_account_from_storage(ByteView encoded) noexcept;

}  // namespace silkworm

#endif  // SILKWORM_TYPES_ACCOUNT_HPP_
