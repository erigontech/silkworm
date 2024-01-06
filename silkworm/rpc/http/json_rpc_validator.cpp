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

#include "json_rpc_validator.hpp"

#include <bit>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#include "json_rpc_specification.hpp"

namespace silkworm::rpc::http {

#define REQUEST_FIELD_METHOD "method"
#define REQUEST_FIELD_ID "id"
#define REQUEST_FIELD_PARAMETERS "params"
#define REQUEST_FIELD_JSONRPC "jsonrpc"

static const std::string valid_jsonrpc_version = "2.0";

JsonRpcValidator::JsonRpcValidator() {
    json_spec = nlohmann::json::parse(silkworm::json_rpc_specification, nullptr, /* allow_exceptions = */ false);
    accept_unknown_methods = true;

    for (const auto& method : json_spec["methods"]) {
        method_params[method["name"]] = method["params"];
    }
}

JsonRpcValidator::JsonRpcValidator(nlohmann::json& spec_) {
    json_spec = spec_;
    accept_unknown_methods = true;
}

JsonRpcValidator::~JsonRpcValidator() {
    // Destructor implementation goes here
}

JsonRpcValidationResults JsonRpcValidator::validate(const nlohmann::json& request_) {
    JsonRpcValidationResults results;
    results.is_valid = true;

    results = check_request_fields(request_);

    if (results.is_valid) {
        results = validate_params(request_);
    }

    return results;
}

JsonRpcValidationResults JsonRpcValidator::check_request_fields(const nlohmann::json& request) {
    JsonRpcValidationResults results;
    results.is_valid = false;

    // expected fields: jsonrpc, method, params (optional), id
    if (request.size() != 4 && request.size() != 3) {
        results.error_message = "Request not valid, required fields: " + std::string(REQUEST_FIELD_METHOD) + ", " + std::string(REQUEST_FIELD_ID) + ", " + std::string(REQUEST_FIELD_PARAMETERS) + ", " + std::string(REQUEST_FIELD_JSONRPC);
        return results;
    }

    // `method` must be a string
    if (!request.contains(REQUEST_FIELD_METHOD) ||
        request[REQUEST_FIELD_METHOD].empty() ||
        !request[REQUEST_FIELD_METHOD].is_string()) {
        results.error_message = "Missing or invalid field: " + std::string(REQUEST_FIELD_METHOD);
        return results;
    }

    // `id` must be a number
    if (!request.contains(REQUEST_FIELD_ID) ||
        request[REQUEST_FIELD_ID].empty() ||
        !request[REQUEST_FIELD_ID].is_number()) {
        results.error_message = "Missing or invalid field: " + std::string(REQUEST_FIELD_ID);
        return results;
    }

    // optional `params` must be an array
    if (request.contains(REQUEST_FIELD_PARAMETERS) && !request[REQUEST_FIELD_PARAMETERS].is_array()) {
        results.error_message = "Invalid field: " + std::string(REQUEST_FIELD_PARAMETERS);
        return results;
    }

    // jsonrpc must contain the string "2.0"
    if (!request.contains(REQUEST_FIELD_JSONRPC) ||
        request[REQUEST_FIELD_JSONRPC] != valid_jsonrpc_version) {
        results.error_message = "Missing or invalid field: " + std::string(REQUEST_FIELD_JSONRPC);
        return results;
    }

    results.is_valid = true;
    return results;
}

JsonRpcValidationResults JsonRpcValidator::validate_params(const nlohmann::json& request) {
    JsonRpcValidationResults results;
    results.is_valid = true;

    auto method = request[REQUEST_FIELD_METHOD];
    auto params = request.contains(REQUEST_FIELD_PARAMETERS) ? request[REQUEST_FIELD_PARAMETERS] : nlohmann::json::array();

    nlohmann::json method_spec;

    if (method_params.find(method) != method_params.end()) {
        method_spec = method_params[method];
    } else {
        results.is_valid = accept_unknown_methods;
        results.error_message = "Method not found in spec";
        return results;
    }

    if (params.size() > method_spec.size()) {
        results.is_valid = false;
        results.error_message = "Invalid number of parameters";
        return results;
    }

    unsigned long idx = 0;
    for (const auto& spec : method_spec) {
        auto spec_name = spec["name"].get<std::string>();
        auto spec_required = spec["required"].get<bool>();
        auto spec_schema = spec["schema"];

        // std::cout << spec_name << " idx: " << idx << " params size: " << params.size() << std::endl;

        if (params.size() <= idx) {
            if (spec_required) {
                results.is_valid = false;
                results.error_message += "\nMissing required parameter: " + spec_name;
            }
            break;
        }

        // std::cout << "params[idx]: " << params[idx] << std::endl;

        if (!spec_schema["type"].is_null()) {
            auto param_results = validate_schema(params[idx], spec_schema);
            if (!param_results.is_valid) {
                results.is_valid = false;
                results.error_message += "\nInvalid parameter: " + spec_name + " " + param_results.error_message;
            }
        }

        nlohmann::json schemas = spec_schema["anyOf"].is_null() ? spec_schema["oneOf"] : spec_schema["anyOf"];
        if (!schemas.is_null()) {
            bool is_valid = false;
            for (const auto& schema : schemas) {
                JsonRpcValidationResults param_results = validate_schema(params[idx], schema);
                if (param_results.is_valid) {
                    is_valid = true;
                    break;
                }
            }

            if (!is_valid) {
                results.is_valid = false;
                results.error_message += "\nInvalid parameter: " + spec_name;
            }
        }

        ++idx;
    }

    return results;
}

JsonRpcValidationResults JsonRpcValidator::validate_schema(const nlohmann::json& value_, const nlohmann::json& schema) {
    JsonRpcValidationResults results;
    results.is_valid = false;

    if (schema["type"] == "string") {
        results = validate_string(value_, schema);
    } else if (schema["type"] == "array") {
        results = validate_array(value_, schema);
    } else if (schema["type"] == "object") {
        results = validate_object(value_, schema);
    } else if (schema["type"] == "boolean") {
        results = validate_boolean(value_);
    } else if (schema["type"] == "number") {
        results = validate_number(value_);
    } else if (schema["type"] == "null") {
        results = validate_null(value_);
    } else {
        results.is_valid = false;
        results.error_message = "Invalid schema type";
    }

    return results;
}

JsonRpcValidationResults JsonRpcValidator::validate_string(const nlohmann::json& string_, const nlohmann::json& schema) {
    JsonRpcValidationResults results;
    results.is_valid = false;

    if (!string_.is_string()) {
        results.error_message = "Invalid string";
        return results;
    }

    if (schema.find("pattern") != schema.end()) {

        std::regex pattern;
        if (regexes.find(schema["pattern"]) != regexes.end()) {
            pattern = regexes[schema["pattern"]];
        } else {
            pattern = std::regex(schema["pattern"].get<std::string>(), std::regex::optimize);
            regexes[schema["pattern"]] = pattern;
        }
        if (!std::regex_match(string_.get<std::string>(), pattern)) {
            results.error_message = "Invalid string pattern";
            return results;
        }
    }

    if (schema.find("enum") != schema.end()) {
        bool is_valid = false;
        for (const auto& enum_value : schema["enum"]) {
            if (string_ == enum_value) {
                is_valid = true;
                break;
            }
        }

        if (!is_valid) {
            results.error_message = "Invalid string enum";
            return results;
        }
    }

    results.is_valid = true;
    return results;
}

JsonRpcValidationResults JsonRpcValidator::validate_array(const nlohmann::json& array_, const nlohmann::json& schema) {
    JsonRpcValidationResults results;
    results.is_valid = true;

    if (!array_.is_array()) {
        results.is_valid = false;
        results.error_message = "Invalid array";
    }

    for (const auto& item : array_) {
        results = validate_schema(item, schema["items"]);
        if (!results.is_valid) {
            break;
        }
    }

    return results;
}

JsonRpcValidationResults JsonRpcValidator::validate_object(const nlohmann::json& object_, const nlohmann::json& schema) {
    JsonRpcValidationResults results;
    results.is_valid = true;

    if (!object_.is_object()) {
        results.is_valid = false;
        results.error_message = "Invalid object";
    }

    if (schema.contains("required")) {
        for (const auto& item : schema["required"]) {
            if (object_.find(item) == object_.end()) {
                results.is_valid = false;
                results.error_message = "Missing required field: " + item.get<std::string>();
                return results;
            }
        }
    }

    if (schema.contains("properties")) {
        for (const auto& item : object_.items()) {
            if (schema["properties"].contains(item.key())) {
                results = validate_schema(item.value(), schema["properties"][item.key()]);
                if (!results.is_valid) {
                    return results;
                }
            } else {
                results.is_valid = false;
                results.error_message = "Invalid field: " + item.key();
                return results;
            }
        }
    }

    return results;
}

JsonRpcValidationResults JsonRpcValidator::validate_boolean(const nlohmann::json& boolean_) {
    JsonRpcValidationResults results;
    results.is_valid = true;

    if (!boolean_.is_boolean()) {
        results.is_valid = false;
        results.error_message = "Invalid boolean";
    }

    return results;
}

JsonRpcValidationResults JsonRpcValidator::validate_number(const nlohmann::json& number_) {
    JsonRpcValidationResults results;
    results.is_valid = true;

    if (!number_.is_number()) {
        results.is_valid = false;
        results.error_message = "Invalid number";
    }

    return results;
}

JsonRpcValidationResults JsonRpcValidator::validate_null(const nlohmann::json&) {
    JsonRpcValidationResults results;
    results.is_valid = true;
    return results;
}

nlohmann::json JsonRpcValidator::get_spec() {
    return json_spec;
}

}  // namespace silkworm::rpc::http