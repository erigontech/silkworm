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

#include <vector>

#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::grpc::interfaces {

::sentry::SentPeers sent_peers_ids_from_peer_keys(const std::vector<sentry::EccPublicKey>& keys);
std::vector<sentry::EccPublicKey> peer_keys_from_sent_peers_ids(const ::sentry::SentPeers& peer_ids);

}  // namespace silkworm::sentry::grpc::interfaces
