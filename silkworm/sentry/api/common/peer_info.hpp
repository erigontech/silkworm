// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include <silkworm/sentry/common/enode_url.hpp>

namespace silkworm::sentry::api {

struct PeerInfo {
    sentry::EnodeUrl url;
    boost::asio::ip::tcp::endpoint local_endpoint;
    boost::asio::ip::tcp::endpoint remote_endpoint;
    bool is_inbound;
    bool is_static;
    std::string client_id;
    std::vector<std::string> capabilities;
};

using PeerInfos = std::vector<PeerInfo>;

}  // namespace silkworm::sentry::api
