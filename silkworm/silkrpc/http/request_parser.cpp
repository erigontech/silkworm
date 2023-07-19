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

#include <picohttpparser.h>

#include <cstdlib>
#include <cstring>

namespace silkworm::rpc::http {

RequestParser::ResultType RequestParser::parse(Request& req, const char* begin, const char* end) {
    const char* method_name;  // uninitialised here because phr_parse_request initialises it
    size_t method_len;        // uninitialised here because phr_parse_request initialises it
    const char* path;         // uninitialised here because phr_parse_request initialises it
    size_t path_len;          // uninitialised here because phr_parse_request initialises it
    int minor_version;        // uninitialised here because phr_parse_request initialises it
    struct phr_header headers[100];
    size_t num_headers = sizeof(headers) / sizeof(headers[0]);
    auto current_len = static_cast<size_t>(end - begin);

    if (req.content_length != 0 && req.content.length() < req.content_length) {
        for (size_t i{0}; i < current_len; ++i) {
            req.content.push_back(begin[i]);
        }
        if (req.content.length() < req.content_length)
            return ResultType::indeterminate;
        else
            return ResultType::good;
    }

    if (last_len_) {
        auto saved_buffer = buffer_;
        buffer_ = new char[last_len_ + current_len];
        std::memcpy(buffer_, saved_buffer, last_len_);
        std::memcpy(buffer_ + last_len_, begin, current_len);
        if (saved_buffer) {
            delete[] saved_buffer;
        }
        begin = buffer_;
        current_len += last_len_;
    }

    const auto res = phr_parse_request(begin, current_len, &method_name, &method_len, &path, &path_len, &minor_version, headers, &num_headers, last_len_);
    if (res == -1) {
        return ResultType::bad;
    } else if (res == -2) {
        auto saved_buffer = buffer_;
        buffer_ = new char[current_len];
        std::memcpy(buffer_, begin, current_len);
        last_len_ = current_len;
        if (saved_buffer)
            delete[] saved_buffer;
        return ResultType::indeterminate;
    }

    bool expect_request = false;
    bool content_length_present = false;

    for (size_t i{0}; i < num_headers; ++i) {
        const auto& header{headers[i]};
        if (header.name_len == 0) continue;
        if (std::memcmp(header.name, "Content-Length", std::min(header.name_len, sizeof("Content-Length"))) == 0) {
            req.content_length = static_cast<uint32_t>(atoi(header.value));
            content_length_present = true;
        } else if (std::memcmp(header.name, "Expect", std::min(header.name_len, sizeof("Expect"))) == 0) {
            expect_request = true;
        } else if (std::memcmp(header.name, "Authorization", std::min(header.name_len, sizeof("Authorization"))) == 0) {
            req.headers.emplace_back();
            for (size_t index = 0; index < static_cast<size_t>(header.name_len); index++) {
                req.headers.back().name.push_back(header.name[index]);
            }
            for (size_t index = 0; index < static_cast<size_t>(header.value_len); index++) {
                req.headers.back().value.push_back(header.value[index]);
            }
        }
    }

    if (!content_length_present) {
        return ResultType::bad;
    }

    if (req.content_length == 0) {
        return ResultType::good;
    }

    req.content.resize(current_len - static_cast<size_t>(res));
    std::memcpy(req.content.data(), begin + res, current_len - static_cast<size_t>(res));
    if (last_len_) {
        last_len_ = 0;
        delete[] buffer_;
        buffer_ = 0;
    }

    if (expect_request)
        return ResultType::processing_continue;
    else if (req.content.length() < req.content_length)
        return ResultType::indeterminate;
    else
        return ResultType::good;
}

}  // namespace silkworm::rpc::http
