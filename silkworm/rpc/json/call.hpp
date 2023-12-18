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

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/call.hpp>

namespace silkworm::rpc {

void from_json(const nlohmann::json&, Call&);
void from_json(const nlohmann::json&, Bundle&);
void from_json(const nlohmann::json&, SimulationContext&);
void from_json(const nlohmann::json&, AccountOverrides&);
void from_json(const nlohmann::json&, BlockOverrides&);
void from_json(const nlohmann::json&, AccountsOverrides&);

void make_glaze_json_content(const nlohmann::json& request_json, const silkworm::Bytes& call_result, std::string& json_reply);

}  // namespace silkworm::rpc
