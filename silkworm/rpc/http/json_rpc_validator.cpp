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
    const auto json_spec = nlohmann::json::parse(silkworm::json_rpc_specification, nullptr, /* allow_exceptions = */ false);
    accept_unknown_methods = true;

    for (const auto& method : json_spec["methods"]) {
        method_params[method["name"].get<std::string>()] = nlohmann::json::parse(method["params"].dump());
    }
}

JsonRpcValidator::JsonRpcValidator(nlohmann::json& spec_) {
    accept_unknown_methods = true;

    for (const auto& method : spec_["methods"]) {
        method_params[method["name"].get<std::string>()] = method["params"];
    }
}

JsonRpcValidator::~JsonRpcValidator() {
}

JsonRpcValidationResults JsonRpcValidator::validate(const nlohmann::json& request_) {
    JsonRpcValidationResults results;
    results.is_valid = true;

    check_request_fields(request_, results);

    if (results.is_valid) {
        validate_params(request_, results);
    }

    return results;
}

void JsonRpcValidator::check_request_fields(const nlohmann::json& request, JsonRpcValidationResults& results) {
    results.is_valid = false;

    // expected fields: jsonrpc, method, params (optional), id
    auto required_fields = 0b111;

    for (auto item = request.begin(); item != request.end(); ++item) {
        if (item.key() == REQUEST_FIELD_METHOD) {
            if (!item.value().is_string()) {
                results.error_message = "Invalid field: " + item.key();
                return;
            }
            required_fields &= 0b110;
        } else if (item.key() == REQUEST_FIELD_ID) {
            if (!item.value().is_number()) {
                results.error_message = "Invalid field: " + item.key();
                return;
            }
            required_fields &= 0b101;
        } else if (item.key() == REQUEST_FIELD_PARAMETERS) {
            if (!item.value().is_array()) {
                results.error_message = "Invalid field: " + item.key();
                return;
            }
        } else if (item.key() == REQUEST_FIELD_JSONRPC) {
            if (!item.value().is_string()) {
                results.error_message = "Invalid field: " + item.key();
                return;
            }
            required_fields &= 0b011;
        } else {
            results.error_message = "Invalid field: " + item.key();
            return;
        }
    }

    if (required_fields != 0) {
        results.error_message = "Request not valid, required fields: " + std::string(REQUEST_FIELD_METHOD) + ", " + std::string(REQUEST_FIELD_ID) + ", " + std::string(REQUEST_FIELD_PARAMETERS) + ", " + std::string(REQUEST_FIELD_JSONRPC);
        return;
    }

    results.is_valid = true;
    return;
}

void JsonRpcValidator::validate_params(const nlohmann::json& request, JsonRpcValidationResults& results) {
    results.is_valid = true;

    const auto method = request.find(REQUEST_FIELD_METHOD).value().get<std::string>();
    const auto params_field = request.find(REQUEST_FIELD_PARAMETERS);
    const auto params = params_field != request.end() ? params_field.value() : nlohmann::json::array();

    const auto method_spec_field = method_params.find(method);
    if (method_spec_field == method_params.end()) {
        results.is_valid = accept_unknown_methods;
        results.error_message = "Method not found in spec";
        return;
    }
    const auto method_spec = method_spec_field->second;

    if (params.size() > method_spec.size()) {
        results.is_valid = false;
        results.error_message = "Invalid number of parameters";
        return;
    }

    unsigned long idx = 0;
    for (const auto& spec : method_spec) {
        const auto spec_name = spec["name"].get<std::string>();
        const auto spec_required = spec["required"].get<bool>();
        const auto spec_schema = spec["schema"];

        if (params.size() <= idx) {
            if (spec_required) {
                results.is_valid = false;
                results.error_message += "\nMissing required parameter: " + spec_name;
            }
            break;
        }

        if (spec_schema.contains("type")) {
            validate_schema(params[idx], spec_schema, results);
            if (!results.is_valid) {
                results.error_message += "\nInvalid parameter: " + spec_name + " " + results.error_message;
                return;
            }
        }

        auto spec_schema_of = spec_schema.find("anyOf");
        if (spec_schema_of == spec_schema.end()) {
            spec_schema_of = spec_schema.find("oneOf");
        }

        if (spec_schema_of != spec_schema.end()) {
            results.is_valid = false;
            for (const auto& schema : spec_schema_of.value()) {
                validate_schema(params[idx], schema, results);
                if (results.is_valid) {
                    results.is_valid = true;
                    break;
                }
            }

            if (!results.is_valid) {
                results.error_message += "\nInvalid parameter: " + spec_name;
            }
        }

        ++idx;
    }

    return;
}

void JsonRpcValidator::validate_schema(const nlohmann::json& value_, const nlohmann::json& schema, JsonRpcValidationResults& results) {
    results.is_valid = false;

    const auto schema_type = schema["type"].get<std::string>();

    if (schema_type == "string") {
        validate_string(value_, schema, results);
    } else if (schema_type == "array") {
        validate_array(value_, schema, results);
    } else if (schema_type == "object") {
        validate_object(value_, schema, results);
    } else if (schema_type == "boolean") {
        validate_boolean(value_, results);
    } else if (schema_type == "number") {
        validate_number(value_, results);
    } else if (schema_type == "null") {
        validate_null(value_, results);
    } else {
        results.is_valid = false;
        results.error_message = "Invalid schema type";
    }

    return;
}

void JsonRpcValidator::validate_string(const nlohmann::json& string_, const nlohmann::json& schema, JsonRpcValidationResults& results) {
    results.is_valid = false;

    if (!string_.is_string()) {
        results.error_message = "Invalid string";
        return;
    }

    const auto schema_pattern_field = schema.find("pattern");
    if (schema_pattern_field != schema.end()) {
        std::regex pattern;
        const auto schema_pattern = schema_pattern_field.value().get<std::string>();
        if (regexes.find(schema_pattern) != regexes.end()) {
            pattern = regexes[schema_pattern];
        } else {
            pattern = std::regex(schema_pattern, std::regex::optimize);
            regexes[schema_pattern] = pattern;
        }
        if (!std::regex_match(string_.get<std::string>(), pattern)) {
            results.error_message = "Invalid string pattern";
            return;
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
            return;
        }
    }

    results.is_valid = true;
    return;
}

void JsonRpcValidator::validate_array(const nlohmann::json& array_, const nlohmann::json& schema, JsonRpcValidationResults& results) {
    results.is_valid = true;

    if (!array_.is_array()) {
        results.is_valid = false;
        results.error_message = "Invalid array";
    }

    const auto schema_items = schema["items"];
    for (const auto& item : array_) {
        validate_schema(item, schema_items, results);
        if (!results.is_valid) {
            break;
        }
    }

    return;
}

void JsonRpcValidator::validate_object(const nlohmann::json& object_, const nlohmann::json& schema, JsonRpcValidationResults& results) {
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
                return;
            }
        }
    }

    if (schema.contains("properties")) {
        for (const auto& item : object_.items()) {
            if (schema["properties"].contains(item.key())) {
                validate_schema(item.value(), schema["properties"][item.key()], results);
                if (!results.is_valid) {
                    return;
                }
            } else {
                results.is_valid = false;
                results.error_message = "Invalid field: " + item.key();
                return;
            }
        }
    }

    return;
}

void JsonRpcValidator::validate_boolean(const nlohmann::json& boolean_, JsonRpcValidationResults& results) {
    results.is_valid = true;

    if (!boolean_.is_boolean()) {
        results.is_valid = false;
        results.error_message = "Invalid boolean";
    }

    return;
}

void JsonRpcValidator::validate_number(const nlohmann::json& number_, JsonRpcValidationResults& results) {
    results.is_valid = true;

    if (!number_.is_number()) {
        results.is_valid = false;
        results.error_message = "Invalid number";
    }

    return;
}

void JsonRpcValidator::validate_null(const nlohmann::json&, JsonRpcValidationResults& results) {
    results.is_valid = true;
    return;
}

}  // namespace silkworm::rpc::http