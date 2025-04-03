// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/remote/kv.pb.h>

#include "../../../api/endpoint/state_change.hpp"

namespace silkworm::db::kv::grpc::client {

::remote::StateChangeRequest request_from_state_change_options(const api::StateChangeOptions&);

api::StateChangeSet state_change_set_from_batch(const ::remote::StateChangeBatch&);

}  // namespace silkworm::db::kv::grpc::client
