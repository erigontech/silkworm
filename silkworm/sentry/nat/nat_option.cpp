// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "nat_option.hpp"

#include <boost/algorithm/string/predicate.hpp>

namespace silkworm::sentry::nat {

bool lexical_cast(const std::string& input, NatOption& value) {
    return lexical_cast(std::string_view{input}, value);
}

bool lexical_cast(std::string_view input, NatOption& value) {
    if (input == "none") {
        value = {};
        return true;
    }
    if (boost::algorithm::istarts_with(input, "extip:")) {
        auto ip_str = input.substr(6);
        boost::system::error_code err;
        auto ip = boost::asio::ip::make_address(ip_str, err);
        value = {NatMode::kExternalIP, {ip}};
        return !err;
    }
    if (input == "stun") {
        value = {NatMode::kStun, std::nullopt};
        return true;
    }
    return false;
}

}  // namespace silkworm::sentry::nat
