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

#include "protocol.hpp"

#include <stdexcept>

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::sentry::eth {

const uint8_t Protocol::kVersion = 68;

void Protocol::handle_peer_first_message(const Message& message) {
    if (message.id != StatusMessage::kId)
        throw std::runtime_error("eth::Protocol: unexpected first message id=" + std::to_string(message.id));

    auto peer_status = StatusMessage::from_message(message);
    auto my_status = status_provider_();

    bool is_compatible =
        (peer_status.version == kVersion) &&
        (peer_status.network_id == my_status.message.network_id) &&
        (peer_status.genesis_hash == my_status.message.genesis_hash) &&
        is_compatible_fork_id(peer_status.fork_id, my_status);

    if (!is_compatible)
        throw Protocol::IncompatiblePeerError();
}

bool Protocol::is_compatible_enr_entry(std::string_view name, ByteView data) {
    if (name == "eth") {
        try {
            auto fork_id = ForkId::rlp_decode_enr_entry(data);
            auto my_status = status_provider_();
            return is_compatible_fork_id(fork_id, my_status);
        } catch (const DecodingException& ex) {
            log::Debug("sentry") << "eth::Protocol::is_compatible_enr_entry failed to decode eth entry data: " << ex.what();
            return false;
        }
    }
    return true;
}

bool Protocol::is_compatible_fork_id(const ForkId& fork_id, const StatusData& my_status) {
    return fork_id.is_compatible_with(
        my_status.message.genesis_hash,
        my_status.fork_block_numbers,
        my_status.fork_block_times,
        my_status.head_block_num);
}

}  // namespace silkworm::sentry::eth
