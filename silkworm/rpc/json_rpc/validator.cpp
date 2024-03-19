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

#include "validator.hpp"

#include <string>

#include <boost/regex.hpp>

#include "specification.hpp"

namespace silkworm::rpc::json_rpc {

static const std::string kRequestFieldJsonRpc{"jsonrpc"};
static const std::string kRequestFieldId{"id"};
static const std::string kRequestFieldMethod{"method"};
static const std::string kRequestFieldParameters{"params"};
static const std::string kRequestRequiredFields{
    kRequestFieldJsonRpc + "," + kRequestFieldId + "," + kRequestFieldMethod + "," + kRequestFieldParameters};

void JsonRpcValidator::load_specification() {
    const auto spec = nlohmann::json::parse(specification_json, nullptr, /*allow_exceptions=*/false);
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
    if (auto valid_result{check_request_fields(request)}; !valid_result) {
        return valid_result;
    }

    return validate_params(request);
}

JsonRpcValidationResult JsonRpcValidator::check_request_fields(const nlohmann::json& request) {
    // Expected fields: jsonrpc, id, method, params (optional)
    auto required_fields = 0b111;

    for (auto item = request.begin(); item != request.end(); ++item) {
        if (item.key() == kRequestFieldMethod) {
            if (!item.value().is_string()) {
                return tl::make_unexpected("Invalid field: " + item.key());
            }
            required_fields &= 0b110;
        } else if (item.key() == kRequestFieldId) {
            if (!item.value().is_number()) {
                return tl::make_unexpected("Invalid field: " + item.key());
            }
            required_fields &= 0b101;
        } else if (item.key() == kRequestFieldParameters) {
            if (!item.value().is_array()) {
                return tl::make_unexpected("Invalid field: " + item.key());
            }
        } else if (item.key() == kRequestFieldJsonRpc) {
            if (!item.value().is_string()) {
                return tl::make_unexpected("Invalid field: " + item.key());
            }
            required_fields &= 0b011;
        } else {
            return tl::make_unexpected("Invalid field: " + item.key());
        }
    }

    if (required_fields != 0) {
        return tl::make_unexpected("Request not valid, required fields: " + kRequestRequiredFields);
    }

    return {};
}

JsonRpcValidationResult JsonRpcValidator::validate_params(const nlohmann::json& request) {
    const auto& method = request.find(kRequestFieldMethod).value().get<std::string>();
    const auto& params_field = request.find(kRequestFieldParameters);
    const auto& params = params_field != request.end() ? params_field.value() : nlohmann::json::array();

    const auto& method_spec_field = method_specs_.find(method);
    if (method_spec_field == method_specs_.end()) {
        if (accept_unknown_methods_) {
            return {};
        } else {
            return tl::make_unexpected("Method not found in spec");
        }
    }
    const auto& method_spec = method_spec_field->second;

    if (params.size() > method_spec.size() + 1) {  // allow one extra parameter for optimize_gas
        return tl::make_unexpected("Invalid number of parameters");
    }

    unsigned long idx = 0;
    for (const auto& spec : method_spec) {
        const auto& spec_name = spec["name"].get<std::string>();
        const auto& spec_schema = spec["schema"];

        if (params.size() <= idx) {
            if (spec.contains("required") && spec["required"].get<bool>()) {
                return tl::make_unexpected("Missing required parameter: " + spec_name);
            }
            break;
        }

        if (auto result{validate_schema(params[idx], spec_schema)}; !result) {
            return tl::make_unexpected("Invalid parameter: " + spec_name);
        }

        ++idx;
    }

    return {};
}

JsonRpcValidationResult JsonRpcValidator::validate_schema(const nlohmann::json& value, const nlohmann::json& schema) {
    if (schema.contains("type")) {
        if (auto result{validate_type(value, schema)}; !result) {
            return result;
        }
    }

    auto schema_of_collection = schema.find("anyOf");
    if (schema_of_collection == schema.end()) {
        schema_of_collection = schema.find("oneOf");
    }

    JsonRpcValidationResult result;
    if (schema_of_collection != schema.end()) {
        for (const auto& schema_of : schema_of_collection.value()) {
            result = validate_type(value, schema_of);
            if (result) {
                break;
            }
        }
    }
    return result;
}

JsonRpcValidationResult JsonRpcValidator::validate_type(const nlohmann::json& value, const nlohmann::json& schema) {
    const auto& schema_type = schema["type"].get<std::string>();

    if (schema_type == "string") {
        return validate_string(value, schema);
    } else if (schema_type == "array") {
        return validate_array(value, schema);
    } else if (schema_type == "object") {
        return validate_object(value, schema);
    } else if (schema_type == "boolean") {
        return validate_boolean(value);
    } else if (schema_type == "number") {
        return validate_number(value);
    } else if (schema_type == "null") {
        return validate_null(value);
    } else {
        return tl::make_unexpected("Invalid schema type");
    }
}

JsonRpcValidationResult JsonRpcValidator::validate_string(const nlohmann::json& string, const nlohmann::json& schema) {
    if (!string.is_string()) {
        return tl::make_unexpected("Invalid string");
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
            return tl::make_unexpected("Invalid string pattern");
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
            return tl::make_unexpected("Invalid string enum");
        }
    }

    return {};
}

JsonRpcValidationResult JsonRpcValidator::validate_array(const nlohmann::json& array, const nlohmann::json& schema) {
    if (!array.is_array() && !array.is_null() && array.empty()) {
        return tl::make_unexpected("Invalid array");
    }

    JsonRpcValidationResult result;
    const auto& schema_items = schema["items"];
    for (const auto& item : array) {
        result = validate_schema(item, schema_items);
        if (!result) {
            return result;
        }
    }

    return result;
}

JsonRpcValidationResult JsonRpcValidator::validate_object(const nlohmann::json& object, const nlohmann::json& schema) {
    if (!object.is_object()) {
        return tl::make_unexpected("Invalid object");
    }

    if (schema.contains("required")) {
        for (const auto& item : schema["required"]) {
            if (object.find(item) == object.end()) {
                return tl::make_unexpected("Missing required field: " + item.get<std::string>());
            }
        }
    }

    if (schema.contains("properties")) {
        for (const auto& item : object.items()) {
            if (schema["properties"].contains(item.key())) {
                if (auto valid_result{validate_schema(item.value(), schema["properties"][item.key()])}; !valid_result) {
                    return valid_result;
                }
            } else if (item.key() == "data") {  // backward compatibility: optional `data` field is hex data
                if (auto valid_result{validate_string(item.value(), R"({"pattern": "^0x[0-9a-f]*$"})"_json)}; !valid_result) {
                    return valid_result;
                }
            } else {
                return tl::make_unexpected("Invalid field: " + item.key());
            }
        }
    }

    return {};
}

JsonRpcValidationResult JsonRpcValidator::validate_boolean(const nlohmann::json& boolean) {
    if (!boolean.is_boolean()) {
        return tl::make_unexpected("Invalid boolean");
    }
    return {};
}

JsonRpcValidationResult JsonRpcValidator::validate_number(const nlohmann::json& number) {
    if (!number.is_number()) {
        return tl::make_unexpected("Invalid number");
    }
    return {};
}

JsonRpcValidationResult JsonRpcValidator::validate_null(const nlohmann::json& value) {
    if (value.is_null() || value.get<std::string>().empty() || value.get<std::string>() == "null") {
        return {};
    }
    return tl::make_unexpected("Invalid null");
}

}  // namespace silkworm::rpc::json_rpc
