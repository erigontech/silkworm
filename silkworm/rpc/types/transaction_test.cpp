/*
   Copyright 2023 The Silkworm Authors

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

#include "transaction.hpp"

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;
using silkworm::kGiga;

TEST_CASE("create empty transaction", "[rpc][types][transaction]") {
    Transaction txn{};
    CHECK(txn.block_hash == evmc::bytes32{});
    CHECK(txn.block_number == 0);
    CHECK(txn.transaction_index == 0);
    CHECK(txn.effective_gas_price() == intx::uint256{0});
}

TEST_CASE("create empty silkworm::transaction", "[rpc][types][silkworm::transaction]") {
    silkworm::Transaction txn{};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << txn);
}

TEST_CASE("print empty transaction", "[rpc][types][transaction]") {
    Transaction txn{};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << txn);
}

TEST_CASE("print type-2 transaction", "[rpc][types][transaction]") {
    // https://etherscan.io/tx/0x4b408a48f927f03a63502fb63f7d42c5c4783737ebe8d084cef157575d40f344
    Transaction txn{};
    txn.type = TransactionType::kDynamicFee;
    txn.chain_id = 1;
    txn.nonce = 371;
    txn.max_priority_fee_per_gas = 1 * kGiga;
    txn.max_fee_per_gas = 217'914'097'876;
    txn.gas_limit = 613'991;
    txn.to = 0x14efa0d4b0f9850ba1787edc730324962446d7cc_address;
    txn.value = 210'000'000 * kGiga;
    txn.data = *from_hex("0x6ecd23060000000000000000000000000000000000000000000000000000000000000005");
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0");
    txn.s = intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a");
    txn.from = 0x7ad75fdb6244111753822140dad3337f5535f718_address;
    txn.block_hash = 0x007fe79ccdd5365f46c34336b8a15b36e05c249a0c62596878236a38034edc21_bytes32;
    txn.block_number = 13116571;
    txn.block_base_fee_per_gas = 110'045'619'790;
    txn.transaction_index = 144;
    CHECK_NOTHROW(silkworm::test_util::null_stream() << txn);
}

TEST_CASE("print type-2 silkworm::transaction", "[rpc][types][silkworm::transaction]") {
    // https://etherscan.io/tx/0x4b408a48f927f03a63502fb63f7d42c5c4783737ebe8d084cef157575d40f344
    silkworm::Transaction txn{};
    txn.type = TransactionType::kDynamicFee;
    txn.chain_id = 1;
    txn.nonce = 371;
    txn.max_priority_fee_per_gas = 1 * kGiga;
    txn.max_fee_per_gas = 217'914'097'876;
    txn.gas_limit = 613'991;
    txn.to = 0x14efa0d4b0f9850ba1787edc730324962446d7cc_address;
    txn.value = 210'000'000 * kGiga;
    txn.data = *from_hex("0x6ecd23060000000000000000000000000000000000000000000000000000000000000005");
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0");
    txn.s = intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a");
    txn.from = 0x7ad75fdb6244111753822140dad3337f5535f718_address;
    CHECK_NOTHROW(silkworm::test_util::null_stream() << txn);
}

TEST_CASE("create legacy transaction", "[rpc][types][transaction]") {
    // https://etherscan.io/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060
    Transaction txn{};
    txn.type = TransactionType::kLegacy;
    txn.nonce = 0;
    txn.max_priority_fee_per_gas = 50'000 * kGiga;
    txn.max_fee_per_gas = 50'000 * kGiga;
    txn.gas_limit = 21'000;
    txn.to = 0x5df9b87991262f6ba471f09758cde1c0fc1de734_address;
    txn.value = 31337;
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0");
    txn.s = intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a");
    txn.from = 0xa1e4380a3b1f749673e270229993ee55f35663b4_address;
    txn.block_hash = 0x4e3a3754410177e6937ef1f84bba68ea139e8d1a2258c5f85db9f1cd715a1bdd_bytes32;
    txn.block_number = 46147;
    CHECK(txn.effective_gas_price() == 50000000000000);
}

TEST_CASE("create legacy silkworm::transaction", "[rpc][types][silkworm::transaction]") {
    // https://etherscan.io/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060
    silkworm::Transaction txn{};
    txn.type = TransactionType::kLegacy;
    txn.nonce = 0;
    txn.max_priority_fee_per_gas = 50'000 * kGiga;
    txn.max_fee_per_gas = 50'000 * kGiga;
    txn.gas_limit = 21'000;
    txn.to = 0x5df9b87991262f6ba471f09758cde1c0fc1de734_address;
    txn.value = 31337;
    txn.odd_y_parity = true;
    txn.r = intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0");
    txn.s = intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a");
    txn.from = 0xa1e4380a3b1f749673e270229993ee55f35663b4_address;
    CHECK_NOTHROW(silkworm::test_util::null_stream() << txn);
}

}  // namespace silkworm::rpc
