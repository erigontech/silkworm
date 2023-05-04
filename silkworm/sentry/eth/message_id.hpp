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

#include <cstdint>

namespace silkworm::sentry::eth {

enum class MessageId : uint8_t {
    kStatus,
    kNewBlockHashes,
    kTransactions,
    kGetBlockHeaders,
    kBlockHeaders,
    kGetBlockBodies,
    kBlockBodies,
    kNewBlock,
    kNewPooledTransactionHashes,
    kGetPooledTransactions,
    kPooledTransactions,
    kGetNodeData = 0xD,  // removed in eth/67
    kNodeData,           // removed in eth/67
    kGetReceipts = 0xF,
    kReceipts,
};

MessageId eth_message_id_from_common_id(uint8_t id);
uint8_t common_message_id_from_eth_id(MessageId eth_id);

}  // namespace silkworm::sentry::eth
