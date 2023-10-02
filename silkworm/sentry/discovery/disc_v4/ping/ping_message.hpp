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

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

#include <boost/asio/ip/udp.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>

namespace silkworm::sentry::discovery::disc_v4::ping {

struct PingMessage {
    boost::asio::ip::udp::endpoint sender_endpoint;
    uint16_t sender_port_rlpx{};
    boost::asio::ip::udp::endpoint recipient_endpoint;
    std::chrono::time_point<std::chrono::system_clock> expiration;
    std::optional<uint64_t> enr_seq_num;

    [[nodiscard]] Bytes rlp_encode() const;
    [[nodiscard]] static PingMessage rlp_decode(ByteView data);

    [[nodiscard]] NodeAddress sender_node_address() const { return {sender_endpoint, sender_port_rlpx}; };

    static const uint8_t kId;
};

}  // namespace silkworm::sentry::discovery::disc_v4::ping
