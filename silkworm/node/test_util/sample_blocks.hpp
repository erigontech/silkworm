/*
   Copyright 2024 The Silkworm Authors

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

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block.hpp>

namespace silkworm::test_util {

using namespace evmc::literals;

inline constexpr auto kSampleBlockHash{0xca39060462327c919e4b08d004b1ba84f59f239ff2fa9f3919f6d4769ba62bfe_bytes32};
inline constexpr auto kSampleParentHash{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};
inline constexpr auto kSampleOmmersHash{0x474f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126d_bytes32};
inline constexpr auto kSampleBeneficiary{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
inline constexpr auto kSampleStateRoot{0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126d_bytes32};
inline constexpr auto kSampleTransactionsRoot{0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126e_bytes32};
inline constexpr auto kSampleReceiptsRoot{0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f_bytes32};
inline constexpr auto kSampleDifficulty{intx::uint256{1234}};
inline constexpr auto kSampleBlockNumber{5u};
inline constexpr auto kSampleGasLimit{1000000u};
inline constexpr auto kSampleGasUsed{1000000u};
inline constexpr auto kSampleTimestamp{5405021u};
inline const Bytes kSampleExtraData{*from_hex("0001FF0100")};
inline constexpr auto kSamplePrevRandao{0x0000000000000000000000000000000000000000000000000000000000000001_bytes32};
inline constexpr auto kSampleNonce{std::array<uint8_t, 8>{0, 0, 0, 0, 0, 0, 0, 255}};
inline constexpr auto kSampleBaseFeePerGas{0x244428u};

inline BlockHeader sample_block_header() {
    return {
        .parent_hash = kSampleParentHash,
        .ommers_hash = kSampleOmmersHash,
        .beneficiary = kSampleBeneficiary,
        .state_root = kSampleStateRoot,
        .transactions_root = kSampleTransactionsRoot,
        .receipts_root = kSampleReceiptsRoot,
        .difficulty = kSampleDifficulty,
        .number = kSampleBlockNumber,
        .gas_limit = kSampleGasLimit,
        .gas_used = kSampleGasUsed,
        .timestamp = kSampleTimestamp,
        .extra_data = kSampleExtraData,
        .prev_randao = kSamplePrevRandao,
        .nonce = kSampleNonce,
        .base_fee_per_gas = kSampleBaseFeePerGas,
    };
}

inline Transaction sample_tx0() {
    Transaction tx;
    tx.nonce = 172339;
    tx.max_priority_fee_per_gas = 50 * kGiga;
    tx.max_fee_per_gas = 50 * kGiga;
    tx.gas_limit = 90'000;
    tx.to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
    tx.value = 1'027'501'080 * kGiga;
    tx.data = {};
    SILKWORM_ASSERT(tx.set_v(27));
    tx.r = intx::from_string<intx::uint256>("0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353");
    tx.s = intx::from_string<intx::uint256>("0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");
    return tx;
}

inline Transaction sample_tx1() {
    Transaction tx;
    tx.type = TransactionType::kDynamicFee;
    tx.nonce = 1;
    tx.max_priority_fee_per_gas = 5 * kGiga;
    tx.max_fee_per_gas = 30 * kGiga;
    tx.gas_limit = 1'000'000;
    tx.to = {};
    tx.value = 0;
    tx.data = *from_hex("602a6000556101c960015560068060166000396000f3600035600055");
    SILKWORM_ASSERT(tx.set_v(37));
    tx.r = intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");
    tx.s = intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");
    return tx;
}

inline constexpr auto kSampleOmmerParentHash{0xb397a22bb95bf14753ec174f02f99df3f0bdf70d1851cdff813ebf745f5aeb55_bytes32};
inline constexpr auto kSampleOmmerBeneficiary{0x0c729be7c39543c3d549282a40395299d987cec2_address};
inline constexpr auto kSampleOmmerStateRoot{0xc2bcdfd012534fa0b19ffba5fae6fc81edd390e9b7d5007d1e92e8e835286e9d_bytes32};
inline constexpr auto kSampleOmmerDifficulty{intx::uint256{12'555'442'155'599}};
inline constexpr auto kSampleOmmerBlockNumber{13'000'013};
inline constexpr auto kSampleOmmerGasLimit{3'141'592};
inline constexpr auto kSampleOmmerGasUsed{0};
inline constexpr auto kSampleOmmerTimestamp{1455404305};
inline constexpr auto kSampleOmmerPrevRandao{0xf0a53dfdd6c2f2a661e718ef29092de60d81d45f84044bec7bf4b36630b2bc08_bytes32};
inline constexpr auto kSampleOmmerNonce{std::array<uint8_t, 8>{0, 0, 0, 0, 0, 0, 0, 35}};

inline BlockHeader sample_ommer0() {
    BlockHeader ommer;
    ommer.parent_hash = kSampleOmmerParentHash;
    ommer.ommers_hash = kEmptyListHash;
    ommer.beneficiary = kSampleOmmerBeneficiary;
    ommer.state_root = kSampleOmmerStateRoot;
    ommer.transactions_root = kEmptyRoot;
    ommer.receipts_root = kEmptyRoot;
    ommer.difficulty = kSampleOmmerDifficulty;
    ommer.number = kSampleOmmerBlockNumber;
    ommer.gas_limit = kSampleOmmerGasLimit;
    ommer.gas_used = kSampleOmmerGasUsed;
    ommer.timestamp = kSampleOmmerTimestamp;
    ommer.prev_randao = kSampleOmmerPrevRandao;
    ommer.nonce = kSampleOmmerNonce;
    return ommer;
}

inline const Transaction kSampleTx0{sample_tx0()};
inline const Transaction kSampleTx1{sample_tx1()};
inline const BlockHeader kSampleOmmer0{sample_ommer0()};

inline constexpr auto kRecipient1{0x40458B394D1C2A9aA095dd169a6EB43a73949fa3_address};
inline constexpr auto kRecipient2{0xEdA2B3743d37a2a5bD4EB018d515DC47B7802EB4_address};
inline const Withdrawal kSampleWithdrawal0{2733, 157233, kRecipient1, 3148401251};
inline const Withdrawal kSampleWithdrawal1{2734, 157234, kRecipient1, 2797715671};
inline const Withdrawal kSampleWithdrawal2{2735, 157235, kRecipient1, 2987093215};
inline const Withdrawal kSampleWithdrawal3{2736, 157236, kRecipient2, 2917273462};

inline BlockBody sample_block_body() {
    BlockBody body;
    body.transactions.emplace_back(kSampleTx0);
    body.transactions.emplace_back(kSampleTx1);

    body.ommers.emplace_back(kSampleOmmer0);

    body.withdrawals = std::vector<Withdrawal>{
        kSampleWithdrawal0,
        kSampleWithdrawal1,
        kSampleWithdrawal2,
        kSampleWithdrawal3,
    };

    return body;
}

inline Block sample_block() {
    Block block{sample_block_body()};
    block.header = sample_block_header();
    return block;
}

}  // namespace silkworm::test_util
