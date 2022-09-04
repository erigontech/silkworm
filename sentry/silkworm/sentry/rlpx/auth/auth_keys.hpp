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

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::rlpx::auth {

struct AuthKeys {
    common::EccPublicKey peer_public_key;

    common::EccPublicKey peer_ephemeral_public_key;
    common::EccKeyPair ephemeral_key_pair;

    Bytes initiator_nonce;
    Bytes recipient_nonce;

    Bytes initiator_first_message_data;
    Bytes recipient_first_message_data;
};

}  // namespace silkworm::sentry::rlpx::auth
