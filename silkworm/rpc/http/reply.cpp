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
// Reply.cpp
// ~~~~~~~~~
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "reply.hpp"

#include <algorithm>
#include <iterator>
#include <string>
#include <vector>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::http {

namespace status_strings {

    const std::string ok = "HTTP/1.1 200 OK\r\n";                                        // NOLINT(runtime/string)
    const std::string created = "HTTP/1.1 201 Created\r\n";                              // NOLINT(runtime/string)
    const std::string accepted = "HTTP/1.1 202 Accepted\r\n";                            // NOLINT(runtime/string)
    const std::string no_content = "HTTP/1.1 204 No Content\r\n";                        // NOLINT(runtime/string)
    const std::string multiple_choices = "HTTP/1.1 300 Multiple Choices\r\n";            // NOLINT(runtime/string)
    const std::string moved_permanently = "HTTP/1.1 301 Moved Permanently\r\n";          // NOLINT(runtime/string)
    const std::string moved_temporarily = "HTTP/1.1 302 Moved Temporarily\r\n";          // NOLINT(runtime/string)
    const std::string not_modified = "HTTP/1.1 304 Not Modified\r\n";                    // NOLINT(runtime/string)
    const std::string bad_request = "HTTP/1.1 400 Bad Request\r\n";                      // NOLINT(runtime/string)
    const std::string unauthorized = "HTTP/1.1 401 Unauthorized\r\n";                    // NOLINT(runtime/string)
    const std::string forbidden = "HTTP/1.1 403 Forbidden\r\n";                          // NOLINT(runtime/string)
    const std::string not_found = "HTTP/1.1 404 Not Found\r\n";                          // NOLINT(runtime/string)
    const std::string internal_server_error = "HTTP/1.1 500 Internal Server Error\r\n";  // NOLINT(runtime/string)
    const std::string not_implemented = "HTTP/1.1 501 Not Implemented\r\n";              // NOLINT(runtime/string)
    const std::string bad_gateway = "HTTP/1.1 502 Bad Gateway\r\n";                      // NOLINT(runtime/string)
    const std::string service_unavailable = "HTTP/1.1 503 Service Unavailable\r\n";      // NOLINT(runtime/string)
    const std::string processing_continue = "HTTP/1.1 100 Continue\r\n";                 // NOLINT(runtime/string)

}  // namespace status_strings

namespace misc_strings {

    const char name_value_separator[] = {':', ' '};
    const char crlf[] = {'\r', '\n'};

}  // namespace misc_strings

boost::asio::const_buffer to_buffer(StatusType status) {
    switch (status) {
        case StatusType::ok:
            return boost::asio::buffer(status_strings::ok);
        case StatusType::created:
            return boost::asio::buffer(status_strings::created);
        case StatusType::accepted:
            return boost::asio::buffer(status_strings::accepted);
        case StatusType::no_content:
            return boost::asio::buffer(status_strings::no_content);
        case StatusType::multiple_choices:
            return boost::asio::buffer(status_strings::multiple_choices);
        case StatusType::moved_permanently:
            return boost::asio::buffer(status_strings::moved_permanently);
        case StatusType::moved_temporarily:
            return boost::asio::buffer(status_strings::moved_temporarily);
        case StatusType::not_modified:
            return boost::asio::buffer(status_strings::not_modified);
        case StatusType::bad_request:
            return boost::asio::buffer(status_strings::bad_request);
        case StatusType::unauthorized:
            return boost::asio::buffer(status_strings::unauthorized);
        case StatusType::forbidden:
            return boost::asio::buffer(status_strings::forbidden);
        case StatusType::not_found:
            return boost::asio::buffer(status_strings::not_found);
        case StatusType::internal_server_error:
            return boost::asio::buffer(status_strings::internal_server_error);
        case StatusType::not_implemented:
            return boost::asio::buffer(status_strings::not_implemented);
        case StatusType::bad_gateway:
            return boost::asio::buffer(status_strings::bad_gateway);
        case StatusType::service_unavailable:
            return boost::asio::buffer(status_strings::service_unavailable);
        case StatusType::processing_continue:
            return boost::asio::buffer(status_strings::processing_continue);
        default:
            return boost::asio::buffer(status_strings::internal_server_error);
    }
}

std::vector<boost::asio::const_buffer> to_buffers(const std::vector<Header>& headers) {
    std::vector<boost::asio::const_buffer> buffers;
    buffers.reserve(headers.size() * 4);

    for (const auto& header : headers) {
        buffers.push_back(boost::asio::buffer(header.name));
        buffers.push_back(boost::asio::buffer(misc_strings::name_value_separator));
        buffers.push_back(boost::asio::buffer(header.value));
        buffers.push_back(boost::asio::buffer(misc_strings::crlf));
    }

    return buffers;
}

std::vector<boost::asio::const_buffer> to_buffers(StatusType status, const std::vector<Header>& headers) {
    std::vector<boost::asio::const_buffer> buffers;
    buffers.reserve(1 + headers.size() * 4 + 1);
    buffers.push_back(to_buffer(status));

    const auto headers_buf = http::to_buffers(headers);
    copy(headers_buf.begin(), headers_buf.end(), back_inserter(buffers));

    buffers.push_back(boost::asio::buffer(misc_strings::crlf));

    return buffers;
}

std::vector<boost::asio::const_buffer> Reply::to_buffers() const {
    std::vector<boost::asio::const_buffer> buffers;
    buffers.reserve(1 + headers.size() * 4 + 2);
    buffers.push_back(to_buffer(status));

    const auto headers_buf = http::to_buffers(headers);
    copy(headers_buf.begin(), headers_buf.end(), back_inserter(buffers));

    buffers.push_back(boost::asio::buffer(misc_strings::crlf));
    buffers.push_back(boost::asio::buffer(content));

    SILK_TRACE << "Reply::to_buffers buffers: " << buffers;
    return buffers;
}

namespace stock_replies {

    const char ok[] = "";
    const char processing_continue[] = "";
    const char created[] =
        "<html>"
        "<head><title>Created</title></head>"
        "<body><h1>201 Created</h1></body>"
        "</html>";
    const char accepted[] =
        "<html>"
        "<head><title>Accepted</title></head>"
        "<body><h1>202 Accepted</h1></body>"
        "</html>";
    const char no_content[] =
        "<html>"
        "<head><title>No Content</title></head>"
        "<body><h1>204 Content</h1></body>"
        "</html>";
    const char multiple_choices[] =
        "<html>"
        "<head><title>Multiple Choices</title></head>"
        "<body><h1>300 Multiple Choices</h1></body>"
        "</html>";
    const char moved_permanently[] =
        "<html>"
        "<head><title>Moved Permanently</title></head>"
        "<body><h1>301 Moved Permanently</h1></body>"
        "</html>";
    const char moved_temporarily[] =
        "<html>"
        "<head><title>Moved Temporarily</title></head>"
        "<body><h1>302 Moved Temporarily</h1></body>"
        "</html>";
    const char not_modified[] =
        "<html>"
        "<head><title>Not Modified</title></head>"
        "<body><h1>304 Not Modified</h1></body>"
        "</html>";
    const char bad_request[] =
        "<html>"
        "<head><title>Bad Request</title></head>"
        "<body><h1>400 Bad Request</h1></body>"
        "</html>";
    const char unauthorized[] =
        "<html>"
        "<head><title>Unauthorized</title></head>"
        "<body><h1>401 Unauthorized</h1></body>"
        "</html>";
    const char forbidden[] =
        "<html>"
        "<head><title>Forbidden</title></head>"
        "<body><h1>403 Forbidden</h1></body>"
        "</html>";
    const char not_found[] =
        "<html>"
        "<head><title>Not Found</title></head>"
        "<body><h1>404 Not Found</h1></body>"
        "</html>";
    const char internal_server_error[] =
        "<html>"
        "<head><title>Internal Server Error</title></head>"
        "<body><h1>500 Internal Server Error</h1></body>"
        "</html>";
    const char not_implemented[] =
        "<html>"
        "<head><title>Not Implemented</title></head>"
        "<body><h1>501 Not Implemented</h1></body>"
        "</html>";
    const char bad_gateway[] =
        "<html>"
        "<head><title>Bad Gateway</title></head>"
        "<body><h1>502 Bad Gateway</h1></body>"
        "</html>";
    const char service_unavailable[] =
        "<html>"
        "<head><title>Service Unavailable</title></head>"
        "<body><h1>503 Service Unavailable</h1></body>"
        "</html>";

    std::string to_string(StatusType status) {
        switch (status) {
            case StatusType::processing_continue:
                return processing_continue;
            case StatusType::ok:
                return ok;
            case StatusType::created:
                return created;
            case StatusType::accepted:
                return accepted;
            case StatusType::no_content:
                return no_content;
            case StatusType::multiple_choices:
                return multiple_choices;
            case StatusType::moved_permanently:
                return moved_permanently;
            case StatusType::moved_temporarily:
                return moved_temporarily;
            case StatusType::not_modified:
                return not_modified;
            case StatusType::bad_request:
                return bad_request;
            case StatusType::unauthorized:
                return unauthorized;
            case StatusType::forbidden:
                return forbidden;
            case StatusType::not_found:
                return not_found;
            case StatusType::internal_server_error:
                return internal_server_error;
            case StatusType::not_implemented:
                return not_implemented;
            case StatusType::bad_gateway:
                return bad_gateway;
            case StatusType::service_unavailable:
                return service_unavailable;
            default:
                return internal_server_error;
        }
    }

}  // namespace stock_replies

Reply Reply::stock_reply(StatusType status) {
    Reply rep;
    rep.status = status;
    rep.content = stock_replies::to_string(status);

    if (status != StatusType::processing_continue) {
        rep.headers.reserve(2);
        rep.headers.emplace_back(Header{"Content-Length", std::to_string(rep.content.size())});
        rep.headers.emplace_back(Header{"Content-Type", "text/html"});
    }
    return rep;
}

}  // namespace silkworm::rpc::http
