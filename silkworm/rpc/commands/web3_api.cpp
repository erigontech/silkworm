// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "web3_api.hpp"

#include <string>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#web3_clientversion
Task<void> Web3RpcApi::handle_web3_client_version(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto client_version = co_await backend_->client_version();
        reply = make_json_content(request, client_version);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, kServerError, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, kServerError, "unexpected exception");
    }
}

// https://eth.wiki/json-rpc/API#web3_sha3
Task<void> Web3RpcApi::handle_web3_sha3(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid web3_sha3 params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    const auto input_string = params[0].get<std::string>();
    const auto optional_input_bytes = from_hex(input_string);
    if (!optional_input_bytes) {
        auto error_msg = "invalid input: " + input_string;
        SILK_ERROR << error_msg;
        reply = make_json_error(request, kInvalidParams, error_msg);
        co_return;
    }
    auto eth_hash = hash_of(optional_input_bytes.value());
    const auto output = "0x" + silkworm::to_hex({eth_hash.bytes, silkworm::kHashLength});
    reply = make_json_content(request, output);
}

}  // namespace silkworm::rpc::commands
