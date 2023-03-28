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

namespace silkrpc::http {

RequestParser::RequestParser() : state_(method_start) {
}

void RequestParser::reset() {
    state_ = method_start;
}

RequestParser::ResultType RequestParser::consume(Request& req, char input) {
    switch (state_) {
        case method_start:
            if (!is_char(input) || is_ctl(input) || is_tspecial(input)) {
                return ResultType::bad;
            } else {
                state_ = method;
                req.method.push_back(input);
                return ResultType::indeterminate;
            }
        case method:
            if (input == ' ') {
                state_ = uri;
                return ResultType::indeterminate;
            } else if (!is_char(input) || is_ctl(input) || is_tspecial(input)) {
                return ResultType::bad;
            } else {
                req.method.push_back(input);
                return ResultType::indeterminate;
            }
        case uri:
            if (input == ' ') {
                state_ = http_version_h;
                return ResultType::indeterminate;
            } else if (is_ctl(input)) {
                return ResultType::bad;
            } else {
                req.uri.push_back(input);
                return ResultType::indeterminate;
            }
        case http_version_h:
            if (input == 'H') {
                state_ = http_version_t_1;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case http_version_t_1:
            if (input == 'T') {
                state_ = http_version_t_2;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case http_version_t_2:
            if (input == 'T') {
                state_ = http_version_p;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case http_version_p:
            if (input == 'P') {
                state_ = http_version_slash;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case http_version_slash:
            if (input == '/') {
                req.http_version_major = 0;
                req.http_version_minor = 0;
                state_ = http_version_major_start;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case http_version_major_start:
            if (is_digit(input)) {
                req.http_version_major = req.http_version_major * 10 + input - '0';
                state_ = http_version_major;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case http_version_major:
            if (input == '.') {
                state_ = http_version_minor_start;
                return ResultType::indeterminate;
            } else if (is_digit(input)) {
                req.http_version_major = req.http_version_major * 10 + input - '0';
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case http_version_minor_start:
            if (is_digit(input)) {
                req.http_version_minor = req.http_version_minor * 10 + input - '0';
                state_ = http_version_minor;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case http_version_minor:
            if (input == '\r') {
                state_ = expecting_newline_1;
                return ResultType::indeterminate;
            } else if (is_digit(input)) {
                req.http_version_minor = req.http_version_minor * 10 + input - '0';
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case expecting_newline_1:
            if (input == '\n') {
                state_ = header_line_start;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case header_line_start:
            if (input == '\r') {
                state_ = expecting_newline_3;
                return ResultType::indeterminate;
            } else if (!req.headers.empty() && (input == ' ' || input == '\t')) {
                state_ = header_lws;
                return ResultType::indeterminate;
            } else if (!is_char(input) || is_ctl(input) || is_tspecial(input)) {
                return ResultType::bad;
            } else {
                req.headers.emplace_back();
                req.headers.back().name.push_back(input);
                state_ = header_name;
                return ResultType::indeterminate;
            }
        case header_lws:
            if (input == '\r') {
                state_ = expecting_newline_2;
                return ResultType::indeterminate;
            } else if (input == ' ' || input == '\t') {
                return ResultType::indeterminate;
            } else if (is_ctl(input)) {
                return ResultType::bad;
            } else {
                state_ = header_value;
                req.headers.back().value.push_back(input);
                return ResultType::indeterminate;
            }
        case header_name:
            if (input == ':') {
                state_ = space_before_header_value;
                return ResultType::indeterminate;
            } else if (!is_char(input) || is_ctl(input) || is_tspecial(input)) {
                return ResultType::bad;
            } else {
                req.headers.back().name.push_back(input);
                return ResultType::indeterminate;
            }
        case space_before_header_value:
            if (input == ' ') {
                state_ = header_value;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case header_value:
            if (input == '\r') {
                state_ = expecting_newline_2;
                return ResultType::indeterminate;
            } else if (is_ctl(input)) {
                return ResultType::bad;
            } else {
                req.headers.back().value.push_back(input);
                return ResultType::indeterminate;
            }
        case expecting_newline_2:
            if (input == '\n') {
                state_ = header_line_start;
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case expecting_newline_3:
            if (input == '\n') {
                state_ = content_start;
                // Look for Content-Length header to get content size
                if (req.content_length == 0) {
                    const auto it = std::find_if(req.headers.begin(), req.headers.end(), [&](const Header& h) {
                        return h.name == "Content-Length";
                    });
                    if (it == req.headers.end()) {
                        return ResultType::bad;
                    }
                    errno = 0;
                    req.content_length = std::strtol((*it).value.c_str(), nullptr, 0);
                    if (errno == ERANGE) {
                        return ResultType::bad;
                    }
                }
                if (req.content_length == 0) {
                    return ResultType::good;
                }
                // Look for Expect header to handle continuation request
                const auto it = std::find_if(req.headers.begin(), req.headers.end(), [&](const Header& h) {
                    return h == kExpectRequestHeader;
                });
                if (it != req.headers.end()) {
                    return ResultType::processing_continue;
                }
                return ResultType::indeterminate;
            } else {
                return ResultType::bad;
            }
        case content_start:
            req.content.push_back(input);
            if (req.content.length() < req.content_length) {
                return ResultType::indeterminate;
            } else {
                return ResultType::good;
            }
    }
    return ResultType::bad;
}

inline bool RequestParser::is_char(int c) {
    return c >= 0 && c <= 127;
}

inline bool RequestParser::is_ctl(int c) {
    return (c >= 0 && c <= 31) || (c == 127);
}

inline bool RequestParser::is_tspecial(int c) {
    switch (c) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
        case ' ':
        case '\t':
            return true;
        default:
            return false;
    }
}

inline bool RequestParser::is_digit(int c) {
    return c >= '0' && c <= '9';
}

}  // namespace silkrpc::http
