// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <boost/asio/ip/tcp.hpp>

#include <silkworm/sentry/common/enode_url.hpp>

namespace silkworm::sentry::api {

struct NodeInfo {
    sentry::EnodeUrl node_url;
    std::string client_id;
    boost::asio::ip::tcp::endpoint rlpx_server_listen_endpoint;
    uint16_t rlpx_server_port;
};

}  // namespace silkworm::sentry::api
