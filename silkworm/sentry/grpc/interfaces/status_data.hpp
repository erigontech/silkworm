// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>
#include <silkworm/sentry/eth/status_data.hpp>

namespace silkworm::sentry::grpc::interfaces {

eth::StatusData status_data_from_proto(const ::sentry::StatusData& data, uint8_t eth_version);
::sentry::StatusData proto_status_data_from_status_data(const eth::StatusData& data);

}  // namespace silkworm::sentry::grpc::interfaces
