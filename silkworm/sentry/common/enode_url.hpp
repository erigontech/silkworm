// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

    const EccPublicKey& public_key() const { return public_key_; }
    const boost::asio::ip::address& ip() const { return ip_; }
    uint16_t port_disc() const { return port_disc_; }
    uint16_t port_rlpx() const { return port_rlpx_; }

    std::string to_string() const;

    bool operator<(const EnodeUrl& other) const;
    friend bool operator==(const EnodeUrl&, const EnodeUrl&) = default;

  private:
    EccPublicKey public_key_;
    boost::asio::ip::address ip_;
    uint16_t port_disc_;
    uint16_t port_rlpx_;
};

}  // namespace silkworm::sentry
