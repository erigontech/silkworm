// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/sentry/api/common/peer_info.hpp>

namespace silkworm::sentry::grpc::interfaces {

api::PeerInfo peer_info_from_proto_peer_info(const types::PeerInfo& info);
types::PeerInfo proto_peer_info_from_peer_info(const api::PeerInfo&);

api::PeerInfos peer_infos_from_proto_peers_reply(const ::sentry::PeersReply& reply);
::sentry::PeersReply proto_peers_reply_from_peer_infos(const api::PeerInfos&);

std::optional<api::PeerInfo> peer_info_opt_from_proto_peer_reply(const ::sentry::PeerByIdReply& reply);
::sentry::PeerByIdReply proto_peer_reply_from_peer_info_opt(const std::optional<api::PeerInfo>&);

}  // namespace silkworm::sentry::grpc::interfaces
