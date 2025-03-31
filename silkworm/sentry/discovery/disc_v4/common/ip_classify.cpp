// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ip_classify.hpp"

#include <algorithm>
#include <vector>

#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>

namespace silkworm::sentry::discovery::disc_v4 {

using namespace boost::asio::ip;

static const std::vector<network_v4>& networks_lan_v4() {
    static std::vector<network_v4> networks = {
        make_network_v4("10.0.0.0/8"),
        make_network_v4("172.16.0.0/12"),
        make_network_v4("192.168.0.0/16"),
        make_network_v4("169.254.0.0/16"),
    };
    return networks;
}

static const std::vector<network_v6>& networks_lan_v6() {
    static std::vector<network_v6> networks = {
        make_network_v6("fc00::/7"),
        make_network_v6("fe80::/10"),
    };
    return networks;
}

static const std::vector<network_v4>& networks_special_v4() {
    static std::vector<network_v4> networks = {
        make_network_v4("100.64.0.0/10"),
        make_network_v4("192.0.0.0/24"),
        make_network_v4("192.0.0.8/32"),
        make_network_v4("192.0.0.9/32"),
        make_network_v4("192.0.0.10/32"),
        make_network_v4("192.0.0.170/32"),
        make_network_v4("192.0.0.171/32"),
        make_network_v4("192.0.2.0/24"),
        make_network_v4("192.31.196.0/24"),
        make_network_v4("192.52.193.0/24"),
        make_network_v4("192.175.48.0/24"),
        make_network_v4("198.18.0.0/15"),
        make_network_v4("198.51.100.0/24"),
        make_network_v4("203.0.113.0/24"),
        make_network_v4("240.0.0.0/4"),
        make_network_v4("255.255.255.255/32"),
    };
    return networks;
}

static const std::vector<network_v6>& networks_special_v6() {
    static std::vector<network_v6> networks = {
        make_network_v6("100::/64"),
        make_network_v6("2001::/23"),
        make_network_v6("2001:1::1/128"),
        make_network_v6("2001:1::2/128"),
        make_network_v6("2001:2::/48"),
        make_network_v6("2001:3::/32"),
        make_network_v6("2001:4:112::/48"),
        make_network_v6("2001:20::/28"),
        make_network_v6("2001:30::/28"),
        make_network_v6("2001:db8::/32"),
        make_network_v6("2620:4f:8000::/48"),
    };
    return networks;
}

static bool ip_belongs_to_networks_v4(const address_v4& ip, const std::vector<network_v4>& networks) {
    auto predicate = [&ip](const network_v4& network) {
        auto hosts = network.hosts();
        return hosts.find(ip) != hosts.end();
    };
    return std::find_if(networks.begin(), networks.end(), predicate) != networks.end();
}

static bool ip_belongs_to_networks_v6(const address_v6& ip, const std::vector<network_v6>& networks) {
    auto predicate = [&ip](const network_v6& network) {
        auto hosts = network.hosts();
        return hosts.find(ip) != hosts.end();
    };
    return std::find_if(networks.begin(), networks.end(), predicate) != networks.end();
}

static bool ip_is_lan(const address& ip) {
    if (ip.is_v4())
        return ip_belongs_to_networks_v4(ip.to_v4(), networks_lan_v4());
    if (ip.is_v6())
        return ip_belongs_to_networks_v6(ip.to_v6(), networks_lan_v6());
    return false;
}

static bool ip_is_special(const address& ip) {
    if (ip.is_v4())
        return ip_belongs_to_networks_v4(ip.to_v4(), networks_special_v4());
    if (ip.is_v6())
        return ip_belongs_to_networks_v6(ip.to_v6(), networks_special_v6());
    return false;
}

IpAddressType ip_classify(const address& ip) {
    if (ip.is_unspecified())
        return IpAddressType::kUnspecified;
    if (ip.is_loopback())
        return IpAddressType::kLoopback;
    if (ip.is_multicast())
        return IpAddressType::kMulticast;
    if (ip == address_v4::broadcast())
        return IpAddressType::kBroadcast;
    if (ip_is_lan(ip))
        return IpAddressType::kLAN;
    if (ip_is_special(ip))
        return IpAddressType::kSpecial;
    return IpAddressType::kRegular;
}

}  // namespace silkworm::sentry::discovery::disc_v4
