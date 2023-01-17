/*
   Copyright 2022 The Silkworm Authors

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

#include <silkworm/sentry/common/channel.hpp>
#include <silkworm/sentry/eth/status_data.hpp>

#include "send_message_call.hpp"

namespace silkworm::sentry::rpc::common {

struct ServiceState {
    uint8_t eth_version;
    sentry::common::Channel<eth::StatusData>& status_channel;
    sentry::common::Channel<SendMessageCall>& send_message_channel;
};

}  // namespace silkworm::sentry::rpc::common
