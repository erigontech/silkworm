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

#include "request_parser.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "picohttpparser.h"

namespace silkworm::rpc::http {

RequestParser::ResultType RequestParser::parse(Request& req, const char* begin, const char* end) {
    const char* method_name;
    size_t method_len;
    const char* path;
    size_t path_len;
    int minor_version;
    struct phr_header headers[100];
    size_t num_headers;
    size_t last_len = 0;

    size_t slen = static_cast<size_t>(end - begin);

    if (req.content_length != 0 && req.content.length() < req.content_length) {
        for (size_t ii = 0; ii < slen; ii++) {
            req.content.push_back(begin[ii]);
        }
        if (req.content.length() < req.content_length)
            return ResultType::indeterminate;
        else
            return ResultType::good;
    }

    num_headers = sizeof(headers) / sizeof(headers[0]);
    auto res = phr_parse_request(begin, slen, &method_name, &method_len, &path, &path_len, &minor_version, headers, &num_headers, last_len);
    if (res < 0) {
        return ResultType::bad;
    }

    bool expect_request = false;
    bool content_length_present = false;

    for (size_t ii = 0; ii < num_headers; ii++) {
        if (memcmp(headers[ii].name, "Content-Length", headers[ii].name_len) == 0) {
            req.content_length = static_cast<uint32_t>(atoi(headers[ii].value));
            content_length_present = true;
        }

        else if (memcmp(headers[ii].name, "Expect", headers[ii].name_len) == 0) {
            expect_request = true;
        }

        else if (memcmp(headers[ii].name, "Authorization", headers[ii].name_len) == 0) {
            req.headers.emplace_back();
            for (size_t index = 0; index < static_cast<size_t>(headers[ii].name_len); index++) {
                req.headers.back().name.push_back(headers[ii].name[index]);
            }
            for (size_t index = 0; index < static_cast<size_t>(headers[ii].value_len); index++) {
                req.headers.back().value.push_back(headers[ii].value[index]);
            }
        }
    }

    if (content_length_present == false) {
        return ResultType::bad;
    }

    if (req.content_length == 0) {
        return ResultType::good;
    }

    req.content.resize(slen - static_cast<size_t>(res));
    memcpy(req.content.data(), &begin[res], slen - static_cast<size_t>(res));
    if (expect_request == true)
        return ResultType::processing_continue;
    else if (req.content.length() < req.content_length)
        return ResultType::indeterminate;
    else
        return ResultType::good;
}

}  // namespace silkworm::rpc::http
