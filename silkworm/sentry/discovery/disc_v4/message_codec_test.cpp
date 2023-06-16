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

#include "message_codec.hpp"

#include <string_view>

#include <catch2/catch.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

#include "disc_v4_common/packet_type.hpp"
#include "disc_v4_common/unix_timestamp.hpp"
#include "ping/ping_message.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

using namespace disc_v4_common;
using namespace boost::asio::ip;

static common::EccKeyPair test_key_pair() {
    constexpr std::string_view kPrivateKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    return common::EccKeyPair{from_hex(kPrivateKey).value()};
}

TEST_CASE("MessageCodec.ping_encode_and_decode") {
    common::EccKeyPair key_pair = test_key_pair();
    ping::PingMessage expected_ping_message{
        udp::endpoint{make_address("10.0.0.1"), 100},
        101,
        udp::endpoint{make_address("10.0.0.2"), 200},
        std::chrono::system_clock::now(),
    };

    common::Message expected_message{static_cast<uint8_t>(PacketType::kPing), expected_ping_message.rlp_encode()};
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

}  // namespace silkworm::sentry::discovery::disc_v4
