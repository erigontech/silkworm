// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ip_endpoint_option.hpp"

#include <regex>
#include <string>

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

namespace silkworm::cmd::common {

IPEndpointValidator::IPEndpointValidator(bool allow_empty) {
    func_ = [&allow_empty](const std::string& value) -> std::string {
        if (value.empty() && allow_empty) {
            return {};
        }

        const std::regex pattern(R"(([\da-fA-F\.\:]*)\:([\d]*))");
        std::smatch matches;
        if (!std::regex_match(value, matches, pattern)) {
            return "Value " + value + " is not a valid endpoint";
        }

        // Validate IP address
        boost::system::error_code err;
        boost::asio::ip::make_address(matches[1], err).to_string();
        if (err) {
            return "Value " + std::string(matches[1]) + " is not a valid ip address";
        }

        // Validate port
        int port{std::stoi(matches[2])};
        if (port < 1 || port > 65535) {
            return "Value " + std::string(matches[2]) + " is not a valid listening port";
        }

        return {};
    };
}

void add_option_ip_endpoint(CLI::App& cli, const std::string& name, std::string& address, const std::string& description) {
    cli.add_option(name, address, description)
        ->capture_default_str()
        ->check(IPEndpointValidator(/*allow_empty=*/true));
}

}  // namespace silkworm::cmd::common
