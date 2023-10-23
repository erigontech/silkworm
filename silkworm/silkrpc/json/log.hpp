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

#include <silkworm/silkrpc/types/log.hpp>

namespace silkworm::rpc {

void from_json(const nlohmann::json& json, Log& log);
void to_json(nlohmann::json& json, const Log& log);

void make_glaze_json_content(uint32_t id, const Logs& logs, std::string& json_reply);

}  // namespace silkworm::rpc
