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

#include <string>

namespace silkrpc {

// generates jwt token
void generate_jwt_token(const std::string& file_path, std::string& jwt_token);

// load a jwt secret token from provided file path
// if the file doesn't contain the jwt secret token then we generate one
bool load_jwt_token(const std::string& file_path, std::string& jwt_token);

}  // namespace silkrpc
