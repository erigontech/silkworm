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

#include "disconnect_message.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/rlp/encode_vector.hpp>

namespace silkworm::sentry::rlpx {

static Bytes rlp_encode(const auto value) {
    Bytes data;
    rlp::encode(data, value);
    return data;
}

TEST_CASE("DisconnectMessage.rlp_decode") {
    CHECK(DisconnectMessage::rlp_decode(rlp_encode(std::vector<uint8_t>{4})).reason == DisconnectReason::kTooManyPeers);
    CHECK(DisconnectMessage::rlp_decode(rlp_encode(uint8_t(4))).reason == DisconnectReason::kTooManyPeers);
    CHECK(DisconnectMessage::rlp_decode(rlp_encode(std::vector<uint8_t>{})).reason == DisconnectReason::kDisconnectRequested);
    CHECK(DisconnectMessage::rlp_decode(Bytes{}).reason == DisconnectReason::kDisconnectRequested);
}

}  // namespace silkworm::sentry::rlpx
