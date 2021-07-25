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

#ifndef SILKWORM_TYPES_BLOCK_HPP_
#define SILKWORM_TYPES_BLOCK_HPP_

#include <stdint.h>

#include <array>
#include <optional>
#include <vector>

#include <ethash/hash_types.hpp>
#include <intx/intx.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/decode.hpp>
#include <silkworm/types/bloom.hpp>
#include <silkworm/types/transaction.hpp>

namespace silkworm {

struct BlockHeader {
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

    evmc::bytes32 mix_hash{};
    std::array<uint8_t, 8> nonce{};

    std::optional<intx::uint256> base_fee_per_gas{std::nullopt};  // EIP-1559

    evmc::bytes32 hash(bool for_sealing = false) const;
    ethash::hash256 boundary() const;

  private:
    friend rlp::DecodingResult rlp::decode<BlockHeader>(ByteView& from, BlockHeader& to) noexcept;
};

bool operator==(const BlockHeader& a, const BlockHeader& b);

inline bool operator!=(const BlockHeader& a, const BlockHeader& b) { return !(a == b); }

struct BlockBody {
    std::vector<Transaction> transactions;
    std::vector<BlockHeader> ommers;
};

bool operator==(const BlockBody& a, const BlockBody& b);

inline bool operator!=(const BlockBody& a, const BlockBody& b) { return !(a == b); }

struct Block : public BlockBody {
    BlockHeader header;

    void recover_senders();
};

struct BlockWithHash {
    Block block;
    evmc::bytes32 hash;
};

namespace rlp {
    template <>
    DecodingResult decode(ByteView& from, BlockBody& to) noexcept;

    template <>
    DecodingResult decode(ByteView& from, BlockHeader& to) noexcept;

    template <>
    DecodingResult decode(ByteView& from, Block& to) noexcept;
}  // namespace rlp

}  // namespace silkworm

#endif  // SILKWORM_TYPES_BLOCK_HPP_
