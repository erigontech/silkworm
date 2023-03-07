/*
    Copyright 2020 The Silkrpc Authors

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

#include <tuple>

#include "request.hpp"

namespace silkrpc::http {

/// Parser for incoming requests.
class RequestParser {
public:
    /// Construct ready to parse the request method.
    RequestParser();

    /// Reset to initial parser state.
    void reset();

    /// Result of parse.
    enum ResultType { good, bad, indeterminate, processing_continue };

    /// Parse some data. The enum return value is good when a complete request has
    /// been parsed, bad if the data is invalid, indeterminate when more data is
    /// required. The InputIterator return value indicates how much of the input
    /// has been consumed.
    template <typename InputIterator>
    ResultType parse(Request& req, InputIterator begin, InputIterator end) {
        while (begin != end) {
            ResultType result = consume(req, *begin++);
            if (result == good || result == bad || result == processing_continue) {
                return result;
            }
        }

        return indeterminate;
    }

private:
    /// Handle the next character of input.
    ResultType consume(Request& req, char input);

    /// Check if a byte is an HTTP character.
    static bool is_char(int c);

    /// Check if a byte is an HTTP control character.
    static bool is_ctl(int c);

    /// Check if a byte is defined as an HTTP tspecial character.
    static bool is_tspecial(int c);

    /// Check if a byte is a digit.
    static bool is_digit(int c);

    /// The current state of the parser.
    enum State {
        method_start,
        method,
        uri,
        http_version_h,
        http_version_t_1,
        http_version_t_2,
        http_version_p,
        http_version_slash,
        http_version_major_start,
        http_version_major,
        http_version_minor_start,
        http_version_minor,
        expecting_newline_1,
        header_line_start,
        header_lws,
        header_name,
        space_before_header_value,
        header_value,
        expecting_newline_2,
        expecting_newline_3,
        content_start
    } state_;
};

} // namespace silkrpc::http

