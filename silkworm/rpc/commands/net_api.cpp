// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "net_api.hpp"

#include <string>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#net_listening
Task<void> NetRpcApi::handle_net_listening(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        co_await backend_->peers();
        reply = make_json_content(request, true);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_content(request, false);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_content(request, false);
    }
}

// https://eth.wiki/json-rpc/API#net_peercount
Task<void> NetRpcApi::handle_net_peer_count(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto peer_count = co_await backend_->net_peer_count();
        reply = make_json_content(request, to_quantity(peer_count));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#net_version
Task<void> NetRpcApi::handle_net_version(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto net_version = co_await backend_->net_version();
        reply = make_json_content(request, std::to_string(net_version));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

}  // namespace silkworm::rpc::commands
