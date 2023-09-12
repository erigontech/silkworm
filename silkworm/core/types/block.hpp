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

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <ethash/hash_types.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/types/bloom.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/core/types/withdrawal.hpp>

namespace silkworm {

using TotalDifficulty = intx::uint256;

struct BlockId {  // TODO(canepat) rename BlockNumberAndHash
    BlockNum number{};
    Hash hash;
};

BlockNum height(const BlockId& b);

struct ChainHead {
    BlockNum height{};
    Hash hash;
    TotalDifficulty total_difficulty{};
};

struct BlockHeader {
    using NonceType = std::array<uint8_t, 8>;

    evmc::bytes32 parent_hash{};
    evmc::bytes32 ommers_hash{};
    evmc::address beneficiary{};
    evmc::bytes32 state_root{};
    evmc::bytes32 transactions_root{};
    evmc::bytes32 receipts_root{};
    Bloom logs_bloom{};
    intx::uint256 difficulty{};
    uint64_t number{0};
    uint64_t gas_limit{0};
    uint64_t gas_used{0};
    uint64_t timestamp{0};

    Bytes extra_data{};

    evmc::bytes32 prev_randao{};  // mix hash prior to EIP-4399
    NonceType nonce{};

    // Added in London
    std::optional<intx::uint256> base_fee_per_gas{std::nullopt};  // EIP-1559

    // Added in Shanghai
    std::optional<evmc::bytes32> withdrawals_root{std::nullopt};  // EIP-4895

    // Added in Cancun
    std::optional<uint64_t> blob_gas_used{std::nullopt};                  // EIP-4844
    std::optional<uint64_t> excess_blob_gas{std::nullopt};                // EIP-4844
    std::optional<evmc::bytes32> parent_beacon_block_root{std::nullopt};  // EIP-4788

    [[nodiscard]] evmc::bytes32 hash(bool for_sealing = false, bool exclude_extra_data_sig = false) const;

    //! \brief Calculates header's boundary. This is described by Equation(50) by the Yellow Paper.
    //! \return A hash of 256 bits with big endian byte order
    [[nodiscard]] ethash::hash256 boundary() const;

    //! \see https://eips.ethereum.org/EIPS/eip-4844#gas-accounting
    [[nodiscard]] std::optional<intx::uint256> blob_gas_price() const;

    friend bool operator==(const BlockHeader&, const BlockHeader&) = default;
};

struct BlockBody {
    std::vector<Transaction> transactions;
    std::vector<BlockHeader> ommers;
    std::optional<std::vector<Withdrawal>> withdrawals{std::nullopt};

    friend bool operator==(const BlockBody&, const BlockBody&) = default;
};

struct Block : public BlockBody {
    BlockHeader header;

    void recover_senders();
};

struct BlockWithHash {
    Block block;
    evmc::bytes32 hash;
};

namespace rlp {
    size_t length(const BlockHeader&);
    size_t length(const BlockBody&);
    size_t length(const Block&);

    void encode(Bytes& to, const BlockBody&);
    void encode(Bytes& to, const BlockHeader&, bool for_sealing = false, bool exclude_extra_data_sig = false);
    void encode(Bytes& to, const Block&);

    DecodingResult decode(ByteView& from, BlockBody& to, Leftover mode = Leftover::kProhibit) noexcept;
    DecodingResult decode(ByteView& from, BlockHeader& to, Leftover mode = Leftover::kProhibit) noexcept;
    DecodingResult decode(ByteView& from, Block& to, Leftover mode = Leftover::kProhibit) noexcept;
}  // namespace rlp

// Comparison operator ==
inline bool operator==(const BlockId& a, const BlockId& b) {
    return a.number == b.number && a.hash == b.hash;
}

inline bool operator==(const ChainHead& a, const BlockId& b) {
    return a.height == b.number && a.hash == b.hash;
}

inline bool operator==(const BlockId& a, const ChainHead& b) {
    return a.number == b.height && a.hash == b.hash;
}

inline bool operator==(const ChainHead& a, const ChainHead& b) {
    return a.height == b.height && a.hash == b.hash && a.total_difficulty == b.total_difficulty;
}

inline BlockId to_BlockId(const ChainHead& head) {
    return {.number = head.height, .hash = head.hash};
}

}  // namespace silkworm
