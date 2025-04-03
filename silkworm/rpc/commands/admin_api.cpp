// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "admin_api.hpp"

#include <string>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#admin_nodeinfo
Task<void> AdminRpcApi::handle_admin_node_info(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto node_infos = co_await backend_->engine_node_info();
        if (!node_infos.empty()) {
            reply = make_json_content(request, node_infos[0]);
        } else {
            reply = make_json_content(request, nlohmann::json::object());
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#admin_peers
Task<void> AdminRpcApi::handle_admin_peers(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto peers = co_await backend_->peers();
        reply = make_json_content(request, peers);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

}  // namespace silkworm::rpc::commands
