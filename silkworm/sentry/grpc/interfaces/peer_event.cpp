// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "peer_event.hpp"

#include "peer_id.hpp"

namespace silkworm::sentry::grpc::interfaces {

namespace proto = ::sentry;

api::PeerEvent peer_event_from_proto_peer_event(const proto::PeerEvent& event) {
    api::PeerEventId event_id{api::PeerEventId::kRemoved};
    switch (event.event_id()) {
        case proto::PeerEvent_PeerEventId_Connect:
            event_id = api::PeerEventId::kAdded;
            break;
        case proto::PeerEvent_PeerEventId_Disconnect:
            event_id = api::PeerEventId::kRemoved;
            break;
        default:
            SILKWORM_ASSERT(false);
    }

    return api::PeerEvent{
        {peer_public_key_from_id(event.peer_id())},
        event_id,
    };
}

proto::PeerEvent proto_peer_event_from_peer_event(const api::PeerEvent& event) {
    proto::PeerEvent reply;
    if (event.peer_public_key) {
        reply.mutable_peer_id()->CopyFrom(peer_id_from_public_key(event.peer_public_key.value()));
    }
    switch (event.event_id) {
        case api::PeerEventId::kAdded:
            reply.set_event_id(proto::PeerEvent_PeerEventId_Connect);
            break;
        case api::PeerEventId::kRemoved:
            reply.set_event_id(proto::PeerEvent_PeerEventId_Disconnect);
            break;
    }
    return reply;
}

}  // namespace silkworm::sentry::grpc::interfaces
