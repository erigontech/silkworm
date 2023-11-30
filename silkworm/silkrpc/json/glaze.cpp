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

#include "glaze.hpp"

#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc {

static constexpr auto errorMessageSize = 1024;
struct GlazeJsonError {
    int code;
    char message[errorMessageSize];
    struct glaze {
        using T = GlazeJsonError;
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
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "error", &T::json_error);
    };
};

void make_glaze_json_error(const nlohmann::json& request_json, const int code, const std::string& message, std::string& json_reply) {
    GlazeJsonErrorRsp glaze_json_error;

    glaze_json_error.id = make_jsonrpc_id(request_json);
    glaze_json_error.json_error.code = code;
    std::strncpy(glaze_json_error.json_error.message, message.c_str(), message.size() > errorMessageSize ? errorMessageSize : message.size() + 1);

    glz::write_json(glaze_json_error, json_reply);
}

struct GlazeJsonRevert {
    int code;
    char message[errorMessageSize];
    std::string data;
    struct glaze {
        using T = GlazeJsonRevert;
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
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "error", &T::revert_data);
    };
};

void make_glaze_json_error(const nlohmann::json& request_json, const RevertError& error, std::string& reply) {
    GlazeJsonRevertError glaze_json_revert;

    glaze_json_revert.id = make_jsonrpc_id(request_json);
    glaze_json_revert.revert_data.code = error.code;
    std::strncpy(glaze_json_revert.revert_data.message, error.message.c_str(), error.message.size() > errorMessageSize ? errorMessageSize : error.message.size() + 1);
    glaze_json_revert.revert_data.data = "0x" + silkworm::to_hex(error.data);

    glz::write_json(glaze_json_revert, reply);
}

}  // namespace silkworm::rpc
