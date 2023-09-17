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
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::crypto::ecdsa_signature {

Bytes sign_recoverable(ByteView data_hash, ByteView private_key);
EccPublicKey verify_and_recover(ByteView data_hash, ByteView signature_and_recovery_id);

Bytes sign(ByteView data_hash, ByteView private_key);
bool verify(ByteView data_hash, ByteView signature_data, const EccPublicKey& public_key);

}  // namespace silkworm::sentry::crypto::ecdsa_signature
