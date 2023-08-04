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

#include <silkworm/sentry/common/ecc_public_key.hpp>

#include "find_node_message.hpp"
#include "neighbors_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::find {

struct MessageHandler {
    virtual ~MessageHandler() = default;
    virtual Task<void> on_find_node(FindNodeMessage message, EccPublicKey sender_public_key, boost::asio::ip::udp::endpoint sender_endpoint) = 0;
    virtual Task<void> on_neighbors(NeighborsMessage message, EccPublicKey sender_public_key) = 0;
};

}  // namespace silkworm::sentry::discovery::disc_v4::find
