// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>

namespace silkworm::sentry::grpc::interfaces {

uint8_t eth_version_from_protocol(::sentry::Protocol protocol);
::sentry::Protocol protocol_from_eth_version(uint8_t version);

}  // namespace silkworm::sentry::grpc::interfaces
