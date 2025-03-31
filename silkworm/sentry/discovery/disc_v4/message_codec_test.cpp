// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "message_codec.hpp"

#include <map>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/unix_timestamp.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

#include "common/packet_type.hpp"
#include "find/find_node_message.hpp"
#include "find/neighbors_message.hpp"
#include "ping/ping_message.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

using namespace boost::asio::ip;

static EccKeyPair test_key_pair() {
    constexpr std::string_view kPrivateKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    return EccKeyPair{from_hex(kPrivateKey).value()};
}

TEST_CASE("MessageCodec.ping_encode_and_decode") {
    EccKeyPair key_pair = test_key_pair();
    ping::PingMessage expected_ping_message{
        udp::endpoint{make_address("10.0.0.1"), 100},
        101,
        udp::endpoint{make_address("10.0.0.2"), 200},
        std::chrono::system_clock::now(),
        123,
    };

    Message expected_message{static_cast<uint8_t>(PacketType::kPing), expected_ping_message.rlp_encode()};
    Bytes expected_message_data = MessageCodec::encode(expected_message, key_pair.private_key());

    auto [decoded_message, decoded_public_key, decoded_packet_hash] = MessageCodec::decode(expected_message_data);
    CHECK(static_cast<PacketType>(decoded_message.id) == PacketType::kPing);
    CHECK(decoded_message.data == expected_message.data);
    CHECK(decoded_public_key == key_pair.public_key());
    CHECK(decoded_packet_hash.size() == 32);
    CHECK(decoded_packet_hash == MessageCodec::encoded_packet_hash(expected_message_data));

    auto decoded_ping_message = ping::PingMessage::rlp_decode(decoded_message.data);
    CHECK(decoded_ping_message.sender_endpoint == expected_ping_message.sender_endpoint);
    CHECK(decoded_ping_message.sender_port_rlpx == expected_ping_message.sender_port_rlpx);
    CHECK(decoded_ping_message.recipient_endpoint == expected_ping_message.recipient_endpoint);
    CHECK(std::chrono::duration_cast<std::chrono::seconds>(decoded_ping_message.expiration - expected_ping_message.expiration).count() == 0);
    CHECK(decoded_ping_message.enr_seq_num == expected_ping_message.enr_seq_num);
}

TEST_CASE("MessageCodec.ping_decode") {
    Bytes data = from_hex("71dbda3a79554728d4f94411e42ee1f8b0d561c10e1e5f5893367948c6a7d70bb87b235fa28a77070271b6c164a2dce8c7e13a5739b53b5e96f2e5acb0e458a02902f5965d55ecbeb2ebb6cabb8b2b232896a36b737666c55265ad0a68412f250001ea04cb847f000001820cfa8215a8d790000000000000000000000000000000018208ae820d058443b9a355").value();
    auto [decoded_message, decoded_public_key, decoded_packet_hash] = MessageCodec::decode(data);
    CHECK(static_cast<PacketType>(decoded_message.id) == PacketType::kPing);
    CHECK(decoded_public_key == test_key_pair().public_key());

    auto decoded_ping_message = ping::PingMessage::rlp_decode(decoded_message.data);
    CHECK(decoded_ping_message.sender_endpoint.address().to_string() == "127.0.0.1");
    CHECK(decoded_ping_message.sender_endpoint.port() == 3322);
    CHECK(decoded_ping_message.sender_port_rlpx == 5544);
    CHECK(decoded_ping_message.recipient_endpoint.address().to_string() == "::1");
    CHECK(decoded_ping_message.recipient_endpoint.port() == 2222);
    CHECK(decoded_ping_message.expiration == time_point_from_unix_timestamp(1136239445));
}

TEST_CASE("MessageCodec.find_node_decode") {
    Bytes data = from_hex("c7c44041b9f7c7e41934417ebac9a8e1a4c6298f74553f2fcfdcae6ed6fe53163eb3d2b52e39fe91831b8a927bf4fc222c3902202027e5e9eb812195f95d20061ef5cd31d502e47ecb61183f74a504fe04c51e73df81f25c4d506b26db4517490103f84eb840ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f8443b9a35582999983999999280dc62cc8255c73471e0a61da0c89acdc0e035e260add7fc0c04ad9ebf3919644c91cb247affc82b69bd2ca235c71eab8e49737c937a2c396").value();
    auto [decoded_message, decoded_public_key, decoded_packet_hash] = MessageCodec::decode(data);
    CHECK(static_cast<PacketType>(decoded_message.id) == PacketType::kFindNode);
    CHECK(decoded_public_key == test_key_pair().public_key());

    auto find_node_message = find::FindNodeMessage::rlp_decode(decoded_message.data);
    CHECK(find_node_message.target_public_key.hex() == "ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f");
    CHECK(find_node_message.expiration == time_point_from_unix_timestamp(1136239445));
}

TEST_CASE("MessageCodec.neighbors_decode") {
    Bytes data = from_hex("c679fc8fe0b8b12f06577f2e802d34f6fa257e6137a995f6f4cbfc9ee50ed3710faf6e66f932c4c8d81d64343f429651328758b47d3dbc02c4042f0fff6946a50f4a49037a72bb550f3a7872363a83e1b9ee6469856c24eb4ef80b7535bcf99c0004f9015bf90150f84d846321163782115c82115db8403155e1427f85f10a5c9a7755877748041af1bcd8d474ec065eb33df57a97babf54bfd2103575fa829115d224c523596b401065a97f74010610fce76382c0bf32f84984010203040101b840312c55512422cf9b8a4097e9a6ad79402e87a15ae909a4bfefa22398f03d20951933beea1e4dfa6f968212385e829f04c2d314fc2d4e255e0d3bc08792b069dbf8599020010db83c4d001500000000abcdef12820d05820d05b84038643200b172dcfef857492156971f0e6aa2c538d8b74010f8e140811d53b98c765dd2d96126051913f44582e8c199ad7c6d6819e9a56483f637feaac9448aacf8599020010db885a308d313198a2e037073488203e78203e8b8408dcab8618c3253b558d459da53bd8fa68935a719aff8b811197101a4b2b47dd2d47295286fc00cc081bb542d760717d1bdd6bec2c37cd72eca367d6dd3b9df738443b9a355010203b525a138aa34383fec3d2719a0").value();
    auto [decoded_message, decoded_public_key, decoded_packet_hash] = MessageCodec::decode(data);
    CHECK(static_cast<PacketType>(decoded_message.id) == PacketType::kNeighbors);
    CHECK(decoded_public_key == test_key_pair().public_key());

    auto neighbors_message = find::NeighborsMessage::rlp_decode(decoded_message.data);
    CHECK(neighbors_message.expiration == time_point_from_unix_timestamp(1136239445));
    CHECK(neighbors_message.node_addresses.size() == 4);

    std::map<std::string, NodeAddress> expected_nodes = {
        {
            "3155e1427f85f10a5c9a7755877748041af1bcd8d474ec065eb33df57a97babf54bfd2103575fa829115d224c523596b401065a97f74010610fce76382c0bf32",
            NodeAddress{
                udp::endpoint{make_address("99.33.22.55"), 4444},
                4445,
            },
        },
        {
            "312c55512422cf9b8a4097e9a6ad79402e87a15ae909a4bfefa22398f03d20951933beea1e4dfa6f968212385e829f04c2d314fc2d4e255e0d3bc08792b069db",
            NodeAddress{
                udp::endpoint{make_address("1.2.3.4"), 1},
                1,
            },
        },
        {
            "38643200b172dcfef857492156971f0e6aa2c538d8b74010f8e140811d53b98c765dd2d96126051913f44582e8c199ad7c6d6819e9a56483f637feaac9448aac",
            NodeAddress{
                udp::endpoint{make_address("2001:db8:3c4d:15::abcd:ef12"), 3333},
                3333,
            },
        },
        {
            "8dcab8618c3253b558d459da53bd8fa68935a719aff8b811197101a4b2b47dd2d47295286fc00cc081bb542d760717d1bdd6bec2c37cd72eca367d6dd3b9df73",
            NodeAddress{
                udp::endpoint{make_address("2001:db8:85a3:8d3:1319:8a2e:370:7348"), 999},
                1000,
            },
        },
    };

    for (const auto& [expected_public_key_hex, expected_address] : expected_nodes) {
        auto expected_public_key = EccPublicKey::deserialize_hex(expected_public_key_hex);
        REQUIRE(neighbors_message.node_addresses.count(expected_public_key));
        auto& address = neighbors_message.node_addresses[expected_public_key];
        CHECK(address.endpoint == expected_address.endpoint);
        CHECK(address.port_rlpx == expected_address.port_rlpx);
    }
}

}  // namespace silkworm::sentry::discovery::disc_v4
