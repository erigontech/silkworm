// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::grpc::interfaces {

::sentry::SentPeers sent_peers_ids_from_peer_keys(const std::vector<sentry::EccPublicKey>& keys);
std::vector<sentry::EccPublicKey> peer_keys_from_sent_peers_ids(const ::sentry::SentPeers& peer_ids);

}  // namespace silkworm::sentry::grpc::interfaces
