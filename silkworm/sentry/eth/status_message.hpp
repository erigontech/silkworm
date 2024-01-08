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

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/message.hpp>

#include "fork_id.hpp"

namespace silkworm::sentry::eth {

struct StatusMessage {
    [[nodiscard]] Bytes rlp_encode() const;
    [[nodiscard]] static StatusMessage rlp_decode(ByteView data);

    [[nodiscard]] Message to_message() const;
    [[nodiscard]] static StatusMessage from_message(const Message& message);

    uint8_t version{0};
    uint64_t network_id{0};
    intx::uint256 total_difficulty;
    Bytes best_block_hash;
    Bytes genesis_hash;
    ForkId fork_id;

    static const uint8_t kId;
};

}  // namespace silkworm::sentry::eth
