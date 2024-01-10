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

#include <nlohmann/json.hpp>

namespace silkworm::rpc::http {

struct JsonRpcValidationResults {
    bool is_valid{false};
    std::string error_message;
};

class JsonRpcValidator {
  public:
    JsonRpcValidator();
    JsonRpcValidator(const nlohmann::json& spec);
    ~JsonRpcValidator() = default;

    JsonRpcValidationResults validate(const nlohmann::json& request);
    const nlohmann::json& get_spec() const { return spec_; }

  private:
    JsonRpcValidationResults check_request_fields(const nlohmann::json& request);
    JsonRpcValidationResults validate_params(const nlohmann::json& request);
    JsonRpcValidationResults validate_schema(const nlohmann::json& value_, const nlohmann::json& schema);
    JsonRpcValidationResults validate_string(const nlohmann::json& string_, const nlohmann::json& schema);
    JsonRpcValidationResults validate_array(const nlohmann::json& array_, const nlohmann::json& schema);
    JsonRpcValidationResults validate_object(const nlohmann::json& object_, const nlohmann::json& schema);
    JsonRpcValidationResults validate_boolean(const nlohmann::json& boolean_);
    JsonRpcValidationResults validate_number(const nlohmann::json& number_);
    JsonRpcValidationResults validate_null(const nlohmann::json& number_);

    nlohmann::json spec_;
    bool accept_unknown_methods_;
};

}  // namespace silkworm::rpc::http
