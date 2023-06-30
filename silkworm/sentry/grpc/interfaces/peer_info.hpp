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

#include <optional>

#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/sentry/api/common/peer_info.hpp>

namespace silkworm::sentry::grpc::interfaces {

api::PeerInfo peer_info_from_proto_peer_info(const types::PeerInfo& info);
types::PeerInfo proto_peer_info_from_peer_info(const api::PeerInfo& info);

api::PeerInfos peer_infos_from_proto_peers_reply(const ::sentry::PeersReply& reply);
::sentry::PeersReply proto_peers_reply_from_peer_infos(const api::PeerInfos& infos);

std::optional<api::PeerInfo> peer_info_opt_from_proto_peer_reply(const ::sentry::PeerByIdReply& reply);
::sentry::PeerByIdReply proto_peer_reply_from_peer_info_opt(const std::optional<api::PeerInfo>& info_opt);

}  // namespace silkworm::sentry::grpc::interfaces
