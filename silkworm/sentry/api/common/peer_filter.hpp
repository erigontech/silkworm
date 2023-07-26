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

#include <optional>

#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::api {

struct PeerFilter {
    std::optional<size_t> max_peers;
    std::optional<sentry::EccPublicKey> peer_public_key;

    static PeerFilter with_max_peers(size_t max_peers) {
        return {{max_peers}, std::nullopt};
    }

    static PeerFilter with_peer_public_key(sentry::EccPublicKey public_key) {
        return {std::nullopt, {std::move(public_key)}};
    }
};

}  // namespace silkworm::sentry::api
