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

#ifndef SILKWORM_TYPES_TRANSACTION_HPP_
#define SILKWORM_TYPES_TRANSACTION_HPP_

#include <optional>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/rlp/decode.hpp>

namespace silkworm {

// https://eips.ethereum.org/EIPS/eip-2930
struct AccessListEntry {
    evmc::address account{};
    std::vector<evmc::bytes32> storage_keys{};
};

bool operator==(const AccessListEntry& a, const AccessListEntry& b);

struct Transaction {
    // EIP-2718 transaction type
    // https://github.com/ethereum/eth1.0-specs/tree/master/lists/signature-types
    enum class Type : uint8_t {
        kLegacy = 0,
        kEip2930 = 1,
        kEip1559 = 2,
    };

    Type type{Type::kLegacy};

    uint64_t nonce{0};
    intx::uint256 max_priority_fee_per_gas{0};
    intx::uint256 max_fee_per_gas{0};
    uint64_t gas_limit{0};
    std::optional<evmc::address> to{std::nullopt};
    intx::uint256 value{0};
    Bytes data{};

    bool odd_y_parity{false};                             // EIP-155
    std::optional<intx::uint256> chain_id{std::nullopt};  // EIP-155
    intx::uint256 r{0}, s{0};                             // signature

    std::vector<AccessListEntry> access_list{};  // EIP-2930

    std::optional<evmc::address> from{std::nullopt};  // sender recovered from the signature

    intx::uint256 v() const;             // EIP-155
    void set_v(const intx::uint256& v);  // EIP-155

    // Populates the from field with recovered sender.
    // See Yellow Paper, Appendix F "Signing Transactions",
    // https://eips.ethereum.org/EIPS/eip-2 and
    // https://eips.ethereum.org/EIPS/eip-155.
    // If recovery fails the from field is set to null.
    //
    // Precondition: pre_validate_transaction must return kOk.
    void recover_sender();

    intx::uint256 priority_fee_per_gas(const intx::uint256& base_fee_per_gas) const;  // EIP-1559
    intx::uint256 effective_gas_price(const intx::uint256& base_fee_per_gas) const;   // EIP-1559
};

bool operator==(const Transaction& a, const Transaction& b);

namespace rlp {
    // According to EIP-2718, serialized transactions are prepended with 1 byte containing the type
    // (0x01 for EIP-2930 transactions); the same goes for receipts. This is true for signing and
    // transaction root calculation. However, in block body RLP serialized EIP-2718 transactions
    // are additionally wrapped into RLP byte array. (Refer to geth implementation;
    // EIP-2718 is mute on block RLP.)
    void encode(Bytes& to, const Transaction& txn, bool for_signing, bool wrap_eip2718_into_array);

    template <>
    DecodingResult decode(ByteView& from, AccessListEntry& to) noexcept;

    template <>
    DecodingResult decode(ByteView& from, Transaction& to) noexcept;
}  // namespace rlp

}  // namespace silkworm

#endif  // SILKWORM_TYPES_TRANSACTION_HPP_
