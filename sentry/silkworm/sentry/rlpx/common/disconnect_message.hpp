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

#include <silkworm/common/base.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::rlpx {

struct DisconnectMessage {
    [[nodiscard]] Bytes rlp_encode() const;
    [[nodiscard]] static DisconnectMessage rlp_decode(ByteView data);

    [[nodiscard]] sentry::common::Message to_message() const;
    [[nodiscard]] static DisconnectMessage from_message(const sentry::common::Message& message);

    static const uint8_t kId;
    uint8_t reason{0};
};

}  // namespace silkworm::sentry::rlpx
