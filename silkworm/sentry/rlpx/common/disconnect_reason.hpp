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

namespace silkworm::sentry::rlpx {

enum class DisconnectReason : uint8_t {
    DisconnectRequested = 0,
    NetworkError = 1,
    ProtocolError = 2,
    UselessPeer = 3,
    TooManyPeers = 4,
    ClientQuitting = 8,
    PingTimeout = 11,
};

}  // namespace silkworm::sentry::rlpx
