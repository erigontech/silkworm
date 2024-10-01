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

#include "message_id.hpp"

#include "status_message.hpp"

namespace silkworm::sentry::eth {

MessageId eth_message_id_from_common_id(uint8_t message_id) {
    SILKWORM_ASSERT(message_id >= eth::StatusMessage::kId);
    if (message_id < eth::StatusMessage::kId)
        return MessageId::kStatus;

    return static_cast<eth::MessageId>(message_id - eth::StatusMessage::kId);
}

uint8_t common_message_id_from_eth_id(MessageId eth_id) {
    return (static_cast<uint8_t>(eth_id) + eth::StatusMessage::kId);
}

}  // namespace silkworm::sentry::eth
