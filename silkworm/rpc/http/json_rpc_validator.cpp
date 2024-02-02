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

#include <string>

#include <boost/regex.hpp>

#include "json_rpc_specification.hpp"

namespace silkworm::rpc::http {

static const std::string kRequestFieldJsonRpc{"jsonrpc"};
static const std::string kRequestFieldId{"id"};
static const std::string kRequestFieldMethod{"method"};
static const std::string kRequestFieldParameters{"params"};
static const std::string kRequestRequiredFields{
    kRequestFieldJsonRpc + "," + kRequestFieldId + "," + kRequestFieldMethod + "," + kRequestFieldParameters};

void JsonRpcValidator::load_specification() {
    const auto spec = nlohmann::json::parse(json_rpc_specification, nullptr, /*allow_exceptions=*/false);
    if (spec.contains("methods")) {
        for (const auto& method : spec["methods"]) {
            method_specs_[method["name"].get<std::string>()] = method["params"];
        }
    }
    if (spec.contains("openrpc")) {
        openrpc_version_ = spec["openrpc"];
    }
}

JsonRpcValidationResult JsonRpcValidator::validate(const nlohmann::json& request) {
    JsonRpcValidationResult result;

    check_request_fields(request, result);

    if (result.is_valid) {
        validate_params(request, result);
    }

    return result;
}

void JsonRpcValidator::check_request_fields(const nlohmann::json& request, JsonRpcValidationResult& result) {
    // Expected fields: jsonrpc, id, method, params (optional)
    auto required_fields = 0b111;

    for (auto item = request.begin(); item != request.end(); ++item) {
        if (item.key() == kRequestFieldMethod) {
            if (!item.value().is_string()) {
                result.is_valid = false;
                result.error_message = "Invalid field: " + item.key();
                return;
            }
            required_fields &= 0b110;
        } else if (item.key() == kRequestFieldId) {
            if (!item.value().is_number()) {
                result.is_valid = false;
                result.error_message = "Invalid field: " + item.key();
                return;
            }
            required_fields &= 0b101;
        } else if (item.key() == kRequestFieldParameters) {
            if (!item.value().is_array()) {
                result.is_valid = false;
                result.error_message = "Invalid field: " + item.key();
                return;
            }
        } else if (item.key() == kRequestFieldJsonRpc) {
            if (!item.value().is_string()) {
                result.is_valid = false;
                result.error_message = "Invalid field: " + item.key();
                return;
            }
            required_fields &= 0b011;
        } else {
            result.is_valid = false;
            result.error_message = "Invalid field: " + item.key();
            return;
        }
    }

    if (required_fields != 0) {
        result.is_valid = false;
        result.error_message = "Request not valid, required fields: " + kRequestRequiredFields;
        return;
    }
}

void JsonRpcValidator::validate_params(const nlohmann::json& request, JsonRpcValidationResult& result) {
    const auto& method = request.find(kRequestFieldMethod).value().get<std::string>();
    const auto& params_field = request.find(kRequestFieldParameters);
    const auto& params = params_field != request.end() ? params_field.value() : nlohmann::json::array();

    const auto& method_spec_field = method_specs_.find(method);
    if (method_spec_field == method_specs_.end()) {
        result.is_valid = accept_unknown_methods_;
        result.error_message = "Method not found in spec";
        return;
    }
    const auto& method_spec = method_spec_field->second;

    if (params.size() > method_spec.size() + 1) { // allow one extra parameter for optimize_gas
        result.is_valid = false;
        result.error_message = "Invalid number of parameters";
        return;
    }

    unsigned long idx = 0;
    for (const auto& spec : method_spec) {
        const auto& spec_name = spec["name"].get<std::string>();
        const auto& spec_schema = spec["schema"];

        if (params.size() <= idx) {
            if (spec.contains("required") && spec["required"].get<bool>()) {
                result.is_valid = false;
                result.error_message += "\nMissing required parameter: " + spec_name;
            }
            break;
        }

        validate_schema(params[idx], spec_schema, result);

        if (!result.is_valid) {
            result.error_message += "\nInvalid parameter: " + spec_name;
            break;
        }

        ++idx;
    }
}

void JsonRpcValidator::validate_schema(const nlohmann::json& value, const nlohmann::json& schema, JsonRpcValidationResult& result) {
    if (schema.contains("type")) {
        validate_type(value, schema, result);
        if (!result.is_valid) {
            return;
        }
    }

    auto schema_of_collection = schema.find("anyOf");
    if (schema_of_collection == schema.end()) {
        schema_of_collection = schema.find("oneOf");
    }

    if (schema_of_collection != schema.end()) {
        for (const auto& schema_of : schema_of_collection.value()) {
            result.is_valid = true;
            validate_type(value, schema_of, result);
            if (result.is_valid) {
                break;
            }
        }
    }
}

void JsonRpcValidator::validate_type(const nlohmann::json& value, const nlohmann::json& schema, JsonRpcValidationResult& result) {
    const auto& schema_type = schema["type"].get<std::string>();

    if (schema_type == "string") {
        validate_string(value, schema, result);
    } else if (schema_type == "array") {
        validate_array(value, schema, result);
    } else if (schema_type == "object") {
        validate_object(value, schema, result);
    } else if (schema_type == "boolean") {
        validate_boolean(value, result);
    } else if (schema_type == "number") {
        validate_number(value, result);
    } else if (schema_type == "null") {
        validate_null(value, result);
    } else {
        result.is_valid = false;
        result.error_message = "Invalid schema type";
    }
}

void JsonRpcValidator::validate_string(const nlohmann::json& string, const nlohmann::json& schema, JsonRpcValidationResult& result) {
    if (!string.is_string()) {
        result.is_valid = false;
        result.error_message = "Invalid string";
        return;
    }

    const auto& schema_pattern_field = schema.find("pattern");
    if (schema_pattern_field != schema.end()) {
        boost::regex pattern;
        const auto& schema_pattern = schema_pattern_field.value().get<std::string>();

        const auto& pattern_field = patterns_.find(schema_pattern);
        if (pattern_field != patterns_.end()) {
            pattern = pattern_field->second;
        } else {
            pattern = boost::regex(schema_pattern, boost::regex::optimize | boost::regex::icase);
            patterns_[schema_pattern] = pattern;
        }

        if (!boost::regex_match(string.get<std::string>(), pattern)) {
            result.is_valid = false;
            result.error_message = "Invalid string pattern";
            return;
        }
    }

    const auto& enum_field = schema.find("enum");
    if (enum_field != schema.end()) {
        bool is_valid = false;
        for (const auto& enum_value : enum_field.value()) {
            if (string == enum_value) {
                is_valid = true;
                break;
            }
        }

        if (!is_valid) {
            result.is_valid = false;
            result.error_message = "Invalid string enum";
            return;
        }
    }
}

void JsonRpcValidator::validate_array(const nlohmann::json& array_, const nlohmann::json& schema, JsonRpcValidationResult& result) {
    if (!array_.is_array() && !array_.is_null()) {
        result.is_valid = false;
        result.error_message = "Invalid array";
    }

    const auto& schema_items = schema["items"];
    for (const auto& item : array_) {
        validate_schema(item, schema_items, result);
        if (!result.is_valid) {
            break;
        }
    }
}

void JsonRpcValidator::validate_object(const nlohmann::json& object, const nlohmann::json& schema, JsonRpcValidationResult& result) {
    if (!object.is_object()) {
        result.is_valid = false;
        result.error_message = "Invalid object";
    }

    if (schema.contains("required")) {
        for (const auto& item : schema["required"]) {
            if (object.find(item) == object.end()) {
                result.is_valid = false;
                result.error_message = "Missing required field: " + item.get<std::string>();
                return;
            }
        }
    }

    if (schema.contains("properties")) {
        for (const auto& item : object.items()) {
            if (schema["properties"].contains(item.key())) {
                validate_schema(item.value(), schema["properties"][item.key()], result);
                if (!result.is_valid) {
                    return;
                }
            } else if (item.key() == "data") { //backward compability: optional `data` field is hex data
                validate_string(item.value(), R"({"pattern": "^0x[0-9a-f]*$"})"_json, result);
                if (!result.is_valid) {
                    return;
                }
            } else {
                result.is_valid = false;
                result.error_message = "Invalid field: " + item.key();
                return;
            }
        }
    }
}

void JsonRpcValidator::validate_boolean(const nlohmann::json& boolean, JsonRpcValidationResult& result) {
    if (!boolean.is_boolean()) {
        result.is_valid = false;
        result.error_message = "Invalid boolean";
    }
}

void JsonRpcValidator::validate_number(const nlohmann::json& number, JsonRpcValidationResult& result) {
    if (!number.is_number()) {
        result.is_valid = false;
        result.error_message = "Invalid number";
    }
}

void JsonRpcValidator::validate_null(const nlohmann::json& value, JsonRpcValidationResult& result) {
    if (value.is_null() || value.get<std::string>().empty() || value.get<std::string>() == "null") {
        return;
    }
    result.is_valid = false;
    result.error_message = "Invalid null";
}

}  // namespace silkworm::rpc::http