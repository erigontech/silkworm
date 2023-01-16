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

#include "engine.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/cast.hpp>
#include <silkworm/consensus/ethash/engine.hpp>
#include <silkworm/state/in_memory_state.hpp>

namespace silkworm::consensus {

TEST_CASE("Consensus Engine Clique activation") {
    BlockHeader fake_header{};
    auto consensus_engine = engine_factory(kGoerliConfig);  // Clique consensus engine
    CHECK(consensus_engine);
}

TEST_CASE("Clique engine validate_seal") {
    BlockHeader header{};
    header.parent_hash = 0x3df0148d8efc77d4dbc56ceccf0ac7cd2bb8d52527654dc533fb59de3461bec2_bytes32;
    header.ommers_hash = 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32;
    header.state_root = 0xfc1023291dad0aa01fdd9035ca2664e9258db0e525bd347f2e3ee0b908b6977d_bytes32;
    header.transactions_root = 0xbbb32657bbc901fcd52ca0ff341c3e904015d7330e7f8a59c8726e5fe4cef279_bytes32;
    header.receipts_root = 0x05c30736b9fea585167275a47d6752c68b3277bb0b6cc3ec7702e014a9acbde9_bytes32;
    header.number = 6257904; 
    header.difficulty = 2; 
    header.gas_limit = 29999972;
    header.gas_used = 798242;
    header.timestamp = 1643045393;
    header.mix_hash = 0x2f73f29450aad18c0956ec6350524c2910f3be67ec6e80b7b597240a195788e1_bytes32;
    header.nonce = {};

    auto consensus_engine = engine_factory(ChainConfig{.seal_engine = SealEngineType::kClique});  // Clique consensus engine
    CHECK(consensus_engine->validate_seal(header) == ValidationResult::kOk);
}

TEST_CASE("get_beneficiary() && extra_data with seal") {
    BlockHeader header{};
    header.parent_hash = 0x3df0148d8efc77d4dbc56ceccf0ac7cd2bb8d52527654dc533fb59de3461bec2_bytes32;
    header.ommers_hash = 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32;
    header.state_root = 0xfc1023291dad0aa01fdd9035ca2664e9258db0e525bd347f2e3ee0b908b6977d_bytes32;
    header.transactions_root = 0xbbb32657bbc901fcd52ca0ff341c3e904015d7330e7f8a59c8726e5fe4cef279_bytes32;
    header.receipts_root = 0x05c30736b9fea585167275a47d6752c68b3277bb0b6cc3ec7702e014a9acbde9_bytes32;
    header.number = 6257904; 
    header.difficulty = 2; 
    header.gas_limit = 29999972;
    header.gas_used = 798242;
    header.timestamp = 1643045393;
    header.mix_hash = 0x2f73f29450aad18c0956ec6350524c2910f3be67ec6e80b7b597240a195788e1_bytes32;
    header.extra_data = string_view_to_byte_view(
        "d883010a0d846765746888676f312e31372e33856c696e7578000000000000002ab85c52944f7ced556a\
                         389a8044be45c006fca6ab41adf927f05f8c66a5debd68218cc4cf4e578581ca7db3c77efd6bbdabf0d435c5cfa68b5e80aa0798fece01");

    auto consensus_engine = engine_factory(ChainConfig{.seal_engine = SealEngineType::kClique});  // Clique consensus engine
    auto address = consensus_engine->get_beneficiary(header);
    CHECK(address == 0x0000000000000000000000000000000000000000_address); // temporary
}

TEST_CASE("get_beneficiary() && extra_data no seal") {
    BlockHeader header{};
    header.parent_hash = 0x3df0148d8efc77d4dbc56ceccf0ac7cd2bb8d52527654dc533fb59de3461bec2_bytes32;
    header.ommers_hash = 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32;
    header.state_root = 0xfc1023291dad0aa01fdd9035ca2664e9258db0e525bd347f2e3ee0b908b6977d_bytes32;
    header.transactions_root = 0xbbb32657bbc901fcd52ca0ff341c3e904015d7330e7f8a59c8726e5fe4cef279_bytes32;
    header.receipts_root = 0x05c30736b9fea585167275a47d6752c68b3277bb0b6cc3ec7702e014a9acbde9_bytes32;
    header.number = 6257904; 
    header.difficulty = 2; 
    header.gas_limit = 29999972;
    header.gas_used = 798242;
    header.timestamp = 1643045393;
    header.mix_hash = 0x2f73f29450aad18c0956ec6350524c2910f3be67ec6e80b7b597240a195788e1_bytes32;
    header.nonce = {};
    header.extra_data = string_view_to_byte_view("d883010a0d84");

    auto consensus_engine = engine_factory(ChainConfig{.seal_engine = SealEngineType::kClique});  // Clique consensus engine
    auto address = consensus_engine->get_beneficiary(header);
    CHECK(address == 0x0000000000000000000000000000000000000000_address);
}


}  // namespace silkworm::consensus
