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

#include <string>

#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::grpc::interfaces {

sentry::EccPublicKey peer_public_key_from_id(const ::types::H512& peer_id);
::types::H512 peer_id_from_public_key(const sentry::EccPublicKey& key);

std::string peer_id_string_from_public_key(const sentry::EccPublicKey& key);

}  // namespace silkworm::sentry::grpc::interfaces
