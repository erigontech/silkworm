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

#pragma once

#include <array>
#include <string>

#include <boost/regex.hpp>
#include <nlohmann/json.hpp>
#include <tl/expected.hpp>

namespace silkworm::rpc::http {

using JsonRpcValidationResult = tl::expected<void, std::string>;

class JsonRpcValidator {
  public:
    static void load_specification();
    static const std::string& openrpc_version() { return openrpc_version_; }

    JsonRpcValidationResult validate(const nlohmann::json& request);

  private:
    JsonRpcValidationResult check_request_fields(const nlohmann::json& request);
    JsonRpcValidationResult validate_params(const nlohmann::json& request);
    JsonRpcValidationResult validate_schema(const nlohmann::json& value, const nlohmann::json& schema);
    JsonRpcValidationResult validate_type(const nlohmann::json& value, const nlohmann::json& schema);
    JsonRpcValidationResult validate_string(const nlohmann::json& string, const nlohmann::json& schema);
    JsonRpcValidationResult validate_array(const nlohmann::json& array, const nlohmann::json& schema);
    JsonRpcValidationResult validate_object(const nlohmann::json& object, const nlohmann::json& schema);
    JsonRpcValidationResult validate_boolean(const nlohmann::json& boolean);
    JsonRpcValidationResult validate_number(const nlohmann::json& number);
    JsonRpcValidationResult validate_null(const nlohmann::json& value);

    inline static std::string openrpc_version_;
    inline static std::map<std::string, nlohmann::json> method_specs_;
    inline static std::map<std::string, boost::regex> patterns_;
    bool accept_unknown_methods_{true};
};

}  // namespace silkworm::rpc::http
