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

#include <cstddef>
#include <cstdint>
#include <optional>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/rlp/decode.hpp>

namespace silkworm::sentry::discovery::disc_v4::disc_v4_common {

struct NodeAddress {
    boost::asio::ip::udp::endpoint endpoint;
    uint16_t port_rlpx{};
};

//! RLP length
size_t length(const NodeAddress&);
//! RLP encode
void encode(Bytes& to, const NodeAddress&);
DecodingResult decode(ByteView& from, NodeAddress& to, rlp::Leftover mode) noexcept;

Bytes ip_address_to_bytes(const boost::asio::ip::address& ip);
std::optional<boost::asio::ip::address> ip_address_from_bytes(ByteView ip_bytes) noexcept;

}  // namespace silkworm::sentry::discovery::disc_v4::disc_v4_common
