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
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <array>
#include <string>

#include <nlohmann/json.hpp>

namespace silkworm::rpc::http {
    struct JsonRpcValidationResults{
        bool is_valid;
        std::string error_message;
    };
    
    class JsonRpcValidator{
        public:
            JsonRpcValidator();
            JsonRpcValidator(nlohmann::json& spec_);
            ~JsonRpcValidator();
            JsonRpcValidationResults validate(const std::string& input_str);
            nlohmann::json get_spec();
        private:
            nlohmann::json json_spec;
            bool accept_unknown_methods;
            JsonRpcValidationResults check_request_fields(const nlohmann::json& request);
            JsonRpcValidationResults validate_params(const nlohmann::json& request);
            JsonRpcValidationResults validate_schema(const nlohmann::json& value_, const nlohmann::json& schema);
            JsonRpcValidationResults validate_string(const nlohmann::json& string_, const nlohmann::json& schema);
            JsonRpcValidationResults validate_array(const nlohmann::json& array_, const nlohmann::json& schema);
            JsonRpcValidationResults validate_object(const nlohmann::json& object_, const nlohmann::json& schema);
            JsonRpcValidationResults validate_boolean(const nlohmann::json& boolean_);
            JsonRpcValidationResults validate_number(const nlohmann::json& number_);
            JsonRpcValidationResults validate_null(const nlohmann::json& number_);
    };  
}