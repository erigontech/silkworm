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

#include "net_api.hpp"

#include <string>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#net_listening
Task<void> NetRpcApi::handle_net_listening(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto peer_count = co_await backend_->net_peer_count();
        reply = make_json_content(request, peer_count > 0);
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
