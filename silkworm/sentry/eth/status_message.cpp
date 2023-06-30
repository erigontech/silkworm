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

#include "status_message.hpp"

#include <stdexcept>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::sentry::eth {

const uint8_t StatusMessage::kId = 16;

Bytes StatusMessage::rlp_encode() const {
    Bytes data;
    rlp::encode(
        data,
        version,
        network_id,
        total_difficulty,
        best_block_hash,
        genesis_hash,
        fork_id);
    return data;
}

StatusMessage StatusMessage::rlp_decode(ByteView data) {
    StatusMessage message;
    auto result = rlp::decode(
        data,
        rlp::Leftover::kProhibit,
        message.version,
        message.network_id,
        message.total_difficulty,
        message.best_block_hash,
        message.genesis_hash,
        message.fork_id);
    success_or_throw(result, "Failed to decode StatusMessage RLP");
    return message;
}

Message StatusMessage::to_message() const {
    return Message{kId, rlp_encode()};
}

StatusMessage StatusMessage::from_message(const Message& message) {
    return rlp_decode(message.data);
}

}  // namespace silkworm::sentry::eth
