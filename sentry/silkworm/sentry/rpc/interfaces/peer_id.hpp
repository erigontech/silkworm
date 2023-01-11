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

#include <types/types.pb.h>

#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::rpc::interfaces {

::types::H512 peer_id_from_public_key(const sentry::common::EccPublicKey& key);
sentry::common::EccPublicKey peer_public_key_from_id(const ::types::H512& peer_id);

}  // namespace silkworm::sentry::rpc::interfaces
