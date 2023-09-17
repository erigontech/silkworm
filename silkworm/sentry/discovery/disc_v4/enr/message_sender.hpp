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

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>

#include "enr_request_message.hpp"
#include "enr_response_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::enr {

struct MessageSender {
    virtual ~MessageSender() = default;
    virtual Task<void> send_enr_request(EnrRequestMessage message, boost::asio::ip::udp::endpoint recipient) = 0;
    virtual Task<void> send_enr_response(EnrResponseMessage message, boost::asio::ip::udp::endpoint recipient) = 0;
};

}  // namespace silkworm::sentry::discovery::disc_v4::enr
