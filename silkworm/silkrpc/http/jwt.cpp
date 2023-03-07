/*
    Copyright 2020-2021 The Silkrpc Authors
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

#include <fstream>
#include <string>
#include <filesystem>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/http/jwt.hpp>

#include <evmc/evmc.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkrpc {

// generates jwt token
void generate_jwt_token(const std::string& file_path, std::string& jwt_token) {
    const char hex_characters[]={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    // if file doesn't exist we generate one
    if (!std::filesystem::exists(file_path)) {
        std::ofstream{file_path};
    }
    // if no token has been found then we make one
    std::ofstream write_file;
    write_file.open(file_path);

    srand(time(0));
    // Generates a random 32 bytes hex token ( not including prefix )
    for(int i = 0; i < 64; ++i) {
        jwt_token += hex_characters[rand()%16];
    }
    SILKRPC_LOG << "JWT token created: " << "0x" << jwt_token << "\n";
    write_file << "0x" << jwt_token << "\n";
    write_file.close();
}

// load a jwt secret token from provided file path
// if the file doesn't contain the jwt secret token then we generate one
bool load_jwt_token(const std::string& file_path, std::string& jwt_token) {
    std::ifstream read_file;
    read_file.open(file_path);
    SILKRPC_LOG << "Reading JWT secret: " <<  file_path << "\n";

    std::getline(read_file, jwt_token);
    read_file.close();
    // get rid of prefix if we have a token
    if (jwt_token.length() > 1 && jwt_token[0] == '0' && (jwt_token[1] == 'x' || jwt_token[1] == 'X')) {
        jwt_token = jwt_token.substr(2);
    }

    if (jwt_token.length() == 64) {
        SILKRPC_LOG << "JWT secret: " <<  "0x" << jwt_token << "\n";
        return true;
    }
    // if token is of an incorrect size then we return an empty string
    if (jwt_token.length() != 0 && jwt_token.length() != 64) {
        return false;
    }
    // make a jwt token since we dont have one
    generate_jwt_token(file_path, jwt_token);
    return true;
}

} // namespace silkrpc
