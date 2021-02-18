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

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <optional>
#include <silkworm/rlp/decode.hpp>
#include <vector>

namespace silkworm {

static constexpr uint8_t kEip2930TransactionType{1};

// https://eips.ethereum.org/EIPS/eip-2930
struct AccessListEntry {
    evmc::address account{};
    std::vector<evmc::bytes32> storage_keys{};
};

bool operator==(const AccessListEntry& a, const AccessListEntry& b);

struct Transaction {
    std::optional<uint8_t> type{std::nullopt};  // EIP-2718

    uint64_t nonce{0};
    intx::uint256 gas_price{0};
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
    void recover_sender(bool homestead, std::optional<uint64_t> permitted_chain_id);
};

bool operator==(const Transaction& a, const Transaction& b);

namespace rlp {
    void encode(Bytes& to, const Transaction& txn, bool for_signing);

    template <>
    DecodingResult decode(ByteView& from, AccessListEntry& to) noexcept;

    template <>
    DecodingResult decode(ByteView& from, Transaction& to) noexcept;
}  // namespace rlp

}  // namespace silkworm

#endif  // SILKWORM_TYPES_TRANSACTION_HPP_
