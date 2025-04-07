// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>
#include <silkworm/sentry/api/common/peer_event.hpp>

namespace silkworm::sentry::grpc::interfaces {

api::PeerEvent peer_event_from_proto_peer_event(const ::sentry::PeerEvent& event);
::sentry::PeerEvent proto_peer_event_from_peer_event(const api::PeerEvent& event);

}  // namespace silkworm::sentry::grpc::interfaces
