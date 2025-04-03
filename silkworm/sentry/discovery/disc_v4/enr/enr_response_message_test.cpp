// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "enr_response_message.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>

namespace silkworm::sentry::discovery::disc_v4::enr {

TEST_CASE("EnrResponseMessage.rlp_decode") {
    auto message = EnrResponseMessage::rlp_decode(*from_hex("f8bda0d9291b8aeb19fc0bd30ee63ddf06a32b3d0d11f960923d7f5f2f2e4bb35ce51df89ab8405ad679e2553358ece5cd4b081032ffb64c52ea354201a354b1354240ad7df6e8571576a6628e1aaa83674e3deacd79a7cf3c459b2467abd133e338351435f0ad6a83657468cac984fc64ec0483118c30826964827634826970847f00000189736563703235366b31a103df05840e8262ca022aaab57ef93233e305181169f7ab3fdb62917756d345a8c98374637082766583756470827665"));
    auto& record = message.record;
    CHECK(record.public_key == EccPublicKey::deserialize_hex("df05840e8262ca022aaab57ef93233e305181169f7ab3fdb62917756d345a8c9739cf596254d5075281b7a013b6c6aff9b596830a7bfc24ae85f5d14b6efc545"));
    CHECK(record.seq_num == 106);
    REQUIRE(record.address_v4.has_value());
    CHECK(record.address_v4->endpoint.address().to_string() == "127.0.0.1");
    CHECK(record.address_v4->endpoint.port() == 30309);
    CHECK(record.address_v4->port_rlpx == 30309);
    CHECK_FALSE(record.address_v6.has_value());

    REQUIRE(record.eth1_fork_id_data.has_value());
    ByteView eth1_fork_id_data{*record.eth1_fork_id_data};
    CHECK(eth1_fork_id_data.size() == 11);

    // eth1_fork_id_data is RLP([[hash_u32, next_u64]]) where the outer list has a single item.
    // It happens because in geth forkid.ID struct is contained within an enrEntry struct (each struct forms a list).
    // This outer list has an RLP header that decode_header() cuts off.
    auto eth1_fork_id_data_rlp_header = rlp::decode_header(eth1_fork_id_data);
    REQUIRE(eth1_fork_id_data_rlp_header.has_value());
    CHECK(eth1_fork_id_data_rlp_header->list);
    CHECK(eth1_fork_id_data_rlp_header->payload_length == 10);

    // now eth1_fork_id_data is just RLP([hash_u32, next_u64])
    uint32_t eth1_fork_id_hash{0};
    uint64_t eth1_fork_id_next{0};
    auto eth1_fork_id_decode_result = rlp::decode(eth1_fork_id_data, rlp::Leftover::kProhibit, eth1_fork_id_hash, eth1_fork_id_next);
    CHECK(eth1_fork_id_decode_result.has_value());
    if (!eth1_fork_id_decode_result) {
        FAIL("eth1_fork_id_decode_result.error = " + std::to_string(static_cast<int>(eth1_fork_id_decode_result.error())));
    }
    CHECK(eth1_fork_id_hash == 0xFC64EC04);
    CHECK(eth1_fork_id_next == 1150000);

    CHECK_FALSE(record.eth2_fork_id_data.has_value());
    CHECK_FALSE(record.eth2_attestation_subnets_data.has_value());
}

TEST_CASE("EnrResponseMessage.rlp_decode.big_seq_num") {
    auto message = EnrResponseMessage::rlp_decode(*from_hex("f8cca0db48c2d9cd569e608d40ebd8cd4dbb7d225de93dcc5366e1385d412feacf8fabf8a9b840e9201a9daeffb557a377c87f15cacd5539a7b764a16e01d610e359d13e5aa29043a7d1e81fcd3e5d62fae96dbb5c167ec3473087161eb0d73e4d5aa36c561f2286017f0e71b3c483657468c7c684dce96c2d8082696482763482697084416c4665836c6573c10189736563703235366b31a1022b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a82348707184736e6170c08374637082765f8375647082765f"));
    auto& record = message.record;
    CHECK(record.seq_num == 1645214806980);
    REQUIRE(record.address_v4.has_value());
    CHECK(record.address_v4->endpoint.address().to_string() == "65.108.70.101");
    CHECK(record.address_v4->endpoint.port() == 30303);
    CHECK(record.address_v4->port_rlpx == 30303);
}

}  // namespace silkworm::sentry::discovery::disc_v4::enr
