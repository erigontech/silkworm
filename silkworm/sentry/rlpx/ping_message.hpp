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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::rlpx {

struct PingMessage {
    Bytes rlp_encode() const;
    sentry::Message to_message() const;
    static const uint8_t kId;
};

struct PongMessage {
    Bytes rlp_encode() const;
    sentry::Message to_message() const;
    static const uint8_t kId;
};

}  // namespace silkworm::sentry::rlpx
