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

#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <cstdlib>

namespace silkworm::rpc::http {

RequestParser::RequestParser() : state_(method_start) {
}

void RequestParser::reset() {
    state_ = method_start;
}

RequestParser::ResultType RequestParser::parse(Request& req, const char* begin, const char* end) {
    ResultType result = consume(req, begin, end);
    if (result == ResultType::good || result == ResultType::bad || result == ResultType::processing_continue) {
        return result;
    }

    return ResultType::indeterminate;
}

#ifdef notdef
POST / HTTP / 1.1 
Host : localhost : 51515 
User - 
Agent : curl / 7.81.0 
Accept : 
Content - Type : application / json 
Content - Length : 52
#endif

RequestParser::ResultType
RequestParser::consume(Request& req, const char* begin, const char* end) {
    auto increase = 1;
    for (auto ptr = begin; ptr < end; ptr++) {
       printf ("%c",*ptr);
    }
    printf ("\n"); 
    fflush(stdout);
    for (; begin != end; begin += increase) {
        increase = 1;
        auto input = *begin;
        switch (state_) {
            case method_start:
                if (memcmp(begin, "POST / ", 7) == 0) {
                    req.method = "POST";
                    increase = 7;
                    state_ = http_version_h;
                    continue;
                }
                else if (!is_char(input) || is_ctl(input) || is_tspecial(input)) {
                    return ResultType::bad;
                } else {
                    state_ = method;
                    req.method.push_back(input);
                    continue;
                }
            case method:
                if (input == ' ') {
                    state_ = uri;
                    continue;
                } else if (!is_char(input) || is_ctl(input) || is_tspecial(input)) {
                    return ResultType::bad;
                } else {
                    req.method.push_back(input);
                    continue;
                }
            case uri:
                if (input == ' ') {
                    state_ = http_version_h;
                    continue;
                } else if (is_ctl(input)) {
                    return ResultType::bad;
                } else {
                    req.uri.push_back(input);
                    continue;
                }
            case http_version_h:
                if (memcmp(begin, "HTTP/", 5) == 0) {
                    req.http_version_major = 0;
                    req.http_version_minor = 0;
                    state_ = http_version_major_start;
                    increase = 5;
                    continue;
                } else if (input == 'H') {
                    state_ = http_version_t_1;
                    continue;
                } else {
                    return ResultType::bad;
                }
            case http_version_t_1:
                if (input == 'T') {
                    state_ = http_version_t_2;
                    continue;
                } else {
                    return ResultType::bad;
                }
            case http_version_t_2:
                if (input == 'T') {
                    state_ = http_version_p;
                    continue;
                } else {
                    return ResultType::bad;
                }
            case http_version_p:
                if (input == 'P') {
                    state_ = http_version_slash;
                    continue;
                } else {
                    return ResultType::bad;
                }
            case http_version_slash:
                if (input == '/') {
                    req.http_version_major = 0;
                    req.http_version_minor = 0;
                    state_ = http_version_major_start;
                    continue;
                } else {
                    return ResultType::bad;
                }
            case http_version_major_start:
                if (is_digit(input)) {
                    req.http_version_major = req.http_version_major * 10 + input - '0';
                    state_ = http_version_major;
                    continue;
                } else {
                    return ResultType::bad;
                }
            case http_version_major:
                if (input == '.') {
                    state_ = http_version_minor_start;
                    continue;
                } else if (is_digit(input)) {
                    req.http_version_major = req.http_version_major * 10 + input - '0';
                    continue;
                } else {
                    return ResultType::bad;
                }
            case http_version_minor_start:
                if (is_digit(input)) {
                    req.http_version_minor = req.http_version_minor * 10 + input - '0';
                    state_ = http_version_minor;
                    continue;
                } else {
                    return ResultType::bad;
                }
            case http_version_minor:
                if (input == '\r') {
                    state_ = expecting_newline_1;
                    continue;
                } else if (is_digit(input)) {
                    req.http_version_minor = req.http_version_minor * 10 + input - '0';
                    continue;
                } else {
                    return ResultType::bad;
                }
            case expecting_newline_1:
                if (input == '\n') {
                    state_ = header_line_start;
                    continue;
                } else {
                    return ResultType::bad;
                }
            case header_line_start:
                if (input == '\r') {
                    state_ = expecting_newline_3;
                    continue;
                } else if (!req.headers.empty() && (input == ' ' || input == '\t')) {
                    state_ = header_lws;
                    continue;
                } else if (!is_char(input) || is_ctl(input) || is_tspecial(input)) {
                    return ResultType::bad;
                } else {
                    req.headers.emplace_back();
                    req.headers.back().name.push_back(input);
                    state_ = header_name;
                    continue;
                }
            case header_lws:
                if (input == '\r') {
                    state_ = expecting_newline_2;
                    continue;
                } else if (input == ' ' || input == '\t') {
                    continue;
                } else if (is_ctl(input)) {
                    return ResultType::bad;
                } else {
                    state_ = header_value;
                    req.headers.back().value.push_back(input);
                    continue;
                }
            case header_name:
                if (input == ':') {
                    state_ = space_before_header_value;
                    continue;
                } else if (!is_char(input) || is_ctl(input) || is_tspecial(input)) {
                    return ResultType::bad;
                } else {
                    req.headers.back().name.push_back(input);
                    continue;
                }
            case space_before_header_value:
                if (input == ' ') {
                    state_ = header_value;
                    continue;
                } else {
                    return ResultType::bad;
                }
            case header_value:
                if (input == '\r') {
                    state_ = expecting_newline_2;
                    continue;
                } else if (is_ctl(input)) {
                    return ResultType::bad;
                } else {
                    req.headers.back().value.push_back(input);
                    continue;
                }
            case expecting_newline_2:
                if (input == '\n') {
                    state_ = header_line_start;
                    continue;
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
                        const char* str{it->value.c_str()};
                        char* end_ptr{nullptr};
                        errno = 0;
                        long long len{std::strtoll(str, &end_ptr, 0)};
                        if (errno == ERANGE || end_ptr == str || len < 0 || len > UINT32_MAX) {
                            return ResultType::bad;
                        }
                        req.content_length = static_cast<uint32_t>(len);
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
                    continue;
                } else {
                    return ResultType::bad;
                }

            case content_start:
                size_t bytes_to_be_copied = req.content_length - req.content.length();
                if (bytes_to_be_copied > static_cast<size_t>(end - begin)) {
                    bytes_to_be_copied = static_cast<size_t>(end - begin);
                }

                for (size_t i = 0; i < bytes_to_be_copied; i++) {
                   req.content.push_back(*begin++);
                }
                //memcpy(req.content.data() + req.content.length(), begin, bytes_to_be_copied);

                if (req.content.length() == req.content_length) {
                    return ResultType::good;
                }
                return ResultType::indeterminate;
        }
    }
    return ResultType::indeterminate;
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

}  // namespace silkworm::rpc::http
