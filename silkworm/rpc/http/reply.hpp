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
// reply.hpp
// ~~~~~~~~~
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <string>
#include <vector>

#include <boost/asio/buffer.hpp>

#include "header.hpp"

namespace silkworm::rpc::http {

//! The status of the reply.
enum class StatusType {
    processing_continue = 100,
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    multiple_choices = 300,
    moved_permanently = 301,
    moved_temporarily = 302,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503
};

boost::asio::const_buffer to_buffer(StatusType status);
std::vector<boost::asio::const_buffer> to_buffers(const std::vector<Header>& headers);
std::vector<boost::asio::const_buffer> to_buffers(StatusType status, const std::vector<Header>& headers);

//! A reply to be sent to a client.
struct Reply {
    //! The status of the reply.
    StatusType status{StatusType::internal_server_error};

    //! The headers to be included in the reply.
    std::vector<Header> headers;

    //! The content to be sent in the reply.
    std::string content;

    /**
     * Convert the reply into a vector of buffers. The buffers do not own the
     * underlying memory blocks, therefore the reply object must remain valid and
     * not be changed until the write operation has completed.
     */
    [[nodiscard]] std::vector<boost::asio::const_buffer> to_buffers() const;

    //! Get a stock reply.
    static Reply stock_reply(StatusType status);

    // reset Reply data
    void reset() {
        headers.resize(0);
        content.resize(0);
    }
};

}  // namespace silkworm::rpc::http
