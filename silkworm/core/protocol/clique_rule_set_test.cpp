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

#include "clique_rule_set.hpp"

#include <catch2/catch.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/state/in_memory_state.hpp>

namespace silkworm::protocol {

TEST_CASE("Clique activation") {
    BlockHeader fake_header{};
    auto rule_set = rule_set_factory(kGoerliConfig);  // Clique rule set
    CHECK(rule_set);
}

TEST_CASE("Clique validate_seal") {
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
    header.prev_randao = 0x2f73f29450aad18c0956ec6350524c2910f3be67ec6e80b7b597240a195788e1_bytes32;
    header.nonce = {};

    auto rule_set = rule_set_factory(ChainConfig{.rule_set_config = CliqueConfig{}});
    CHECK(rule_set->validate_seal(header) == ValidationResult::kOk);
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
    header.base_fee_per_gas = 8;
    std::string bloom_str = "0020000000000080100920000000000008000000000000000000000000100000000002000010100000000410000000000000000000000400000";
    bloom_str.append("0080010200000000000004000001021000048000000000000000000000400000000080000002000030000040010808000000000");
    bloom_str.append("0001000000200000000080800000100002000800000100000000002000400000800000000020000000000000900800200000804200400");
    bloom_str.append("000110010000000000004000000008400000000000000008000000c000000000200000004420000000000421000400002000000000000");
    bloom_str.append("0000000000000210000083000820090000200000400100000008000000000000000000000000");
    auto bloom = *from_hex(bloom_str);
    std::copy(bloom.begin(), bloom.end(), header.logs_bloom.begin());
    std::string extra_data_str = "d883010a0d846765746888676f312e31372e33856c696e7578000000000000002ab85c52944f7ced556a";
    extra_data_str.append("389a8044be45c006fca6ab41adf927f05f8c66a5debd68218cc4cf4e578581ca7db3c77efd6bbdabf0d435c5cfa68b5e80aa0798fece01");
    header.extra_data = *from_hex(extra_data_str);
    auto rule_set = rule_set_factory(ChainConfig{.rule_set_config = CliqueConfig{}});
    CHECK(rule_set->get_beneficiary(header) == 0xa6dd2974b96e959f2c8930024451a30afec24203_address);
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
    header.prev_randao = 0x2f73f29450aad18c0956ec6350524c2910f3be67ec6e80b7b597240a195788e1_bytes32;
    header.nonce = {};
    header.extra_data = string_view_to_byte_view("d883010a0d84");
    auto rule_set = rule_set_factory(ChainConfig{.rule_set_config = CliqueConfig{}});
    CHECK(rule_set->get_beneficiary(header) == 0x0000000000000000000000000000000000000000_address);
}

}  // namespace silkworm::protocol
