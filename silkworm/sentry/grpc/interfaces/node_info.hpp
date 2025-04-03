// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/sentry/api/common/node_info.hpp>

namespace silkworm::sentry::grpc::interfaces {

api::NodeInfo node_info_from_proto_node_info(const types::NodeInfoReply& info);
types::NodeInfoReply proto_node_info_from_node_info(const api::NodeInfo& info);

}  // namespace silkworm::sentry::grpc::interfaces
