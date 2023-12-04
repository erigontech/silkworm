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

#include <cstdint>
#include <string>
#include <vector>

#include "header.hpp"

namespace silkworm::rpc::http {

//! A request received from a client.
struct Request {
    std::string method;
    std::string uri;
    int http_version_major{1};
    int http_version_minor{0};
    std::vector<Header> headers;
    uint32_t content_length{0};
    std::string content;

    void reset() {
        method.resize(0);
        uri.resize(0);
        http_version_major = 1;
        http_version_minor = 0;
        headers.resize(0);
        content_length = 0;
        content.resize(0);
    }
};

}  // namespace silkworm::rpc::http
