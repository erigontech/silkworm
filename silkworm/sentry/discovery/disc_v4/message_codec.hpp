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

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::discovery::disc_v4 {

struct MessageEnvelope {
    Message message;
    EccPublicKey public_key;
    Bytes packet_hash;
};

struct MessageCodec {
    static Bytes encode(const Message& message, ByteView private_key);
    static ByteView encoded_packet_hash(ByteView packet_data);
    static MessageEnvelope decode(ByteView packet_data);
};

}  // namespace silkworm::sentry::discovery::disc_v4
