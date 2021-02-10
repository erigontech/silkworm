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

#ifndef SILKWORM_TYPES_TRANSACTION_H_
#define SILKWORM_TYPES_TRANSACTION_H_

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <optional>
#include <silkworm/rlp/decode.hpp>

namespace silkworm {

struct Transaction {
    uint64_t nonce{0};
    intx::uint256 gas_price;
    uint64_t gas_limit{0};
    std::optional<evmc::address> to;
    intx::uint256 value;
    Bytes data;
    intx::uint256 v, r, s;              // signature
    std::optional<evmc::address> from;  // sender recovered from the signature

    // Populates the from field with recovered sender.
    // See Yellow Paper, Appendix F "Signing Transactions",
    // https://eips.ethereum.org/EIPS/eip-2 and
    // https://eips.ethereum.org/EIPS/eip-155.
    // If recovery fails the from field is set to null.
    void recover_sender(bool homestead, std::optional<uint64_t> eip155_chain_id);
};

bool operator==(const Transaction& a, const Transaction& b);

namespace rlp {
    void encode(Bytes& to, const Transaction& txn, bool for_signing, std::optional<uint64_t> eip155_chain_id);

    template <>
    DecodingResult decode(ByteView& from, Transaction& to) noexcept;
}  // namespace rlp
}  // namespace silkworm

#endif  // SILKWORM_TYPES_TRANSACTION_H_
