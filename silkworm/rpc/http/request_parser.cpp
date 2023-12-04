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

//! The default size of HTTP character buffer used by the parser
constexpr std::size_t kDefaultHttpBufferSize{65536};

//! The maximum number of HTTP headers supported by the parser
constexpr std::size_t kMaxHttpHeaders{100};

void RequestParser::reset() {
    prev_len_ = 0;
    buffer_.clear();
}

RequestParser::RequestParser() {
    buffer_.resize(kDefaultHttpBufferSize);
}

RequestParser::ResultType RequestParser::parse(Request& req, const char* begin, const char* end) {
    auto current_len = static_cast<size_t>(end - begin);

    if (req.content_length != 0 && req.content.length() < req.content_length) {
        for (size_t i{0}; i < current_len; i++) {
            req.content.push_back(begin[i]);
        }
        if (req.content.length() < req.content_length)
            return ResultType::indeterminate;
        else
            return ResultType::good;
    }

    if (prev_len_) {
        for (size_t i = 0; i < current_len; i++) {
            buffer_.push_back(*begin++);
        }
        begin = buffer_.data();
        current_len = buffer_.size();
    }

    const char* method_name;  // uninitialised here because phr_parse_request initialises it
    size_t method_len;        // uninitialised here because phr_parse_request initialises it
    const char* path;         // uninitialised here because phr_parse_request initialises it
    size_t path_len;          // uninitialised here because phr_parse_request initialises it
    int minor_version;        // uninitialised here because phr_parse_request initialises it
    struct phr_header headers[kMaxHttpHeaders];
    size_t num_headers = sizeof(headers) / sizeof(headers[0]);

    const auto res = phr_parse_request(begin, current_len, &method_name, &method_len, &path, &path_len, &minor_version, headers, &num_headers, prev_len_);
    if (res == -1) {
        return ResultType::bad;
    } else if (res == -2) {
        buffer_.clear();
        for (size_t i = 0; i < current_len; i++) {
            buffer_.push_back(*begin++);
        }
        prev_len_ = buffer_.size();
        return ResultType::indeterminate;
    }

    req.http_version_minor = minor_version;

    bool expect_request{false};
    bool content_length_present{false};
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

    if (!content_length_present || req.content_length == 0) {
        return ResultType::good;
    }

    req.content.resize(current_len - static_cast<size_t>(res));
    std::memcpy(req.content.data(), begin + res, current_len - static_cast<size_t>(res));

    if (expect_request) {
        return ResultType::processing_continue;
    } else if (req.content.length() < req.content_length) {
        return ResultType::indeterminate;
    } else {
        return ResultType::good;
    }
}

}  // namespace silkworm::rpc::http
