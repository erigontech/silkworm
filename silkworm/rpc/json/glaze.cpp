// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "glaze.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>

#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

//! Maximum size of RPC error message
static constexpr size_t kMaxErrorMessageSize{1024};

//! Fill a fixed error message by trimming the provided message if needed
static void fill_error_message(char fixed_msg[kMaxErrorMessageSize], const std::string& msg) {
    const auto error_message_size{std::min(msg.size(), kMaxErrorMessageSize - 1)};
    std::strncpy(fixed_msg, msg.c_str(), error_message_size);
    fixed_msg[error_message_size] = '\0';
}

struct GlazeJsonError {
    int code{-1};
    char message[kMaxErrorMessageSize]{};
    struct glaze {
        using T = GlazeJsonError;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "code", &T::code,
            "message", &T::message);
    };
};

struct GlazeJsonErrorRsp {
    std::string_view jsonrpc = kJsonVersion;
    JsonRpcId id;
    GlazeJsonError json_error;
    struct glaze {
        using T = GlazeJsonErrorRsp;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "error", &T::json_error);
    };
};

void make_glaze_json_error(const nlohmann::json& request, const int error_id, const std::string& message, std::string& reply) {
    GlazeJsonErrorRsp glaze_json_error{};

    glaze_json_error.id = make_jsonrpc_id(request);
    glaze_json_error.json_error.code = error_id;
    fill_error_message(glaze_json_error.json_error.message, message);

    glz::write_json(glaze_json_error, reply);
}

struct GlazeJsonRevert {
    int code{-1};
    char message[kMaxErrorMessageSize]{};
    std::string data;
    struct glaze {
        using T = GlazeJsonRevert;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "code", &T::code,
            "message", &T::message,
            "data", &T::data);
    };
};

struct GlazeJsonRevertError {
    std::string_view jsonrpc = kJsonVersion;
    JsonRpcId id;
    GlazeJsonRevert revert_data;
    struct glaze {
        using T = GlazeJsonRevertError;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "error", &T::revert_data);
    };
};

void make_glaze_json_error(const nlohmann::json& request, const RevertError& error, std::string& reply) {
    GlazeJsonRevertError glaze_json_revert{};

    glaze_json_revert.id = make_jsonrpc_id(request);
    glaze_json_revert.revert_data.code = error.code;
    fill_error_message(glaze_json_revert.revert_data.message, error.message);
    glaze_json_revert.revert_data.data = "0x" + silkworm::to_hex(error.data);

    glz::write_json(glaze_json_revert, reply);
}

}  // namespace silkworm::rpc
