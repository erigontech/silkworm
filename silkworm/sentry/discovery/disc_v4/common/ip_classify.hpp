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

#include <cstdint>

#include <boost/asio/ip/address.hpp>

namespace silkworm::sentry::discovery::disc_v4 {

enum class IpAddressType : uint8_t {
    kRegular,
    kUnspecified,
    kLoopback,
    kMulticast,
    kBroadcast,
    kLAN,
    // https://www.iana.org/assignments/iana-ipv4-special-registry/
    // https://www.iana.org/assignments/iana-ipv6-special-registry/
    kSpecial,
};

IpAddressType ip_classify(const boost::asio::ip::address& ip);

}  // namespace silkworm::sentry::discovery::disc_v4
