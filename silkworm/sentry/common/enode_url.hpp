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

#pragma once

#include <string>
#include <string_view>

#include <boost/asio/ip/address.hpp>

#include "ecc_public_key.hpp"

namespace silkworm::sentry {

class EnodeUrl {
  public:
    explicit EnodeUrl(std::string_view url_str);

    EnodeUrl(EccPublicKey public_key, boost::asio::ip::address ip, uint16_t port_disc, uint16_t port_rlpx)
        : public_key_(std::move(public_key)),
          ip_(std::move(ip)),
          port_disc_(port_disc),
          port_rlpx_(port_rlpx) {}

    [[nodiscard]] const EccPublicKey& public_key() const { return public_key_; }
    [[nodiscard]] const boost::asio::ip::address& ip() const { return ip_; }
    [[nodiscard]] uint16_t port_disc() const { return port_disc_; }
    [[nodiscard]] uint16_t port_rlpx() const { return port_rlpx_; }

    [[nodiscard]] std::string to_string() const;

    bool operator<(const EnodeUrl& other) const;
    friend bool operator==(const EnodeUrl&, const EnodeUrl&) = default;

  private:
    EccPublicKey public_key_;
    boost::asio::ip::address ip_;
    uint16_t port_disc_;
    uint16_t port_rlpx_;
};

}  // namespace silkworm::sentry
